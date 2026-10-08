// decryptedSize() must report the plaintext size from encryption.xml's
// OriginalLength, not the zip entry size (the encrypted blob). Callers size
// their output buffer from it and reject any mismatch.
#include <Crypto.h>
#include <ProtectedBook.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using freeink::content::ProtectedBook;

struct Source : freeink::content::ByteSource {
  std::vector<uint8_t> bytes;
  uint64_t size() const override { return bytes.size(); }
  int32_t readAt(uint64_t offset, void* dst, uint32_t len) override {
    if (offset > bytes.size() || len > bytes.size() - offset) return -1;
    std::memcpy(dst, bytes.data() + offset, len);
    return static_cast<int32_t>(len);
  }
};

void put(std::vector<uint8_t>& b, uint32_t v, int n) {
  for (int i = 0; i < n; i++) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// Minimal stored (method 0) zip: local headers + data, central directory, EOCD.
Source storedZip(const std::vector<std::pair<std::string, std::string>>& files) {
  Source s;
  std::vector<uint8_t> cd;
  for (const auto& f : files) {
    const uint32_t offset = static_cast<uint32_t>(s.bytes.size());
    const uint32_t size = static_cast<uint32_t>(f.second.size());
    put(s.bytes, 0x04034b50, 4);
    for (int i = 0; i < 4; i++) put(s.bytes, 0, 2);  // version, flags, method, time
    put(s.bytes, 0, 2);                              // date
    put(s.bytes, 0, 4);                              // crc (not checked)
    put(s.bytes, size, 4);
    put(s.bytes, size, 4);
    put(s.bytes, static_cast<uint32_t>(f.first.size()), 2);
    put(s.bytes, 0, 2);
    s.bytes.insert(s.bytes.end(), f.first.begin(), f.first.end());
    s.bytes.insert(s.bytes.end(), f.second.begin(), f.second.end());

    put(cd, 0x02014b50, 4);
    for (int i = 0; i < 6; i++) put(cd, 0, 2);  // versions, flags, method, time, date
    put(cd, 0, 4);
    put(cd, size, 4);
    put(cd, size, 4);
    put(cd, static_cast<uint32_t>(f.first.size()), 2);
    for (int i = 0; i < 4; i++) put(cd, 0, 2);  // extra, comment, disk, internal attrs
    put(cd, 0, 4);
    put(cd, offset, 4);
    cd.insert(cd.end(), f.first.begin(), f.first.end());
  }
  const uint32_t cdOffset = static_cast<uint32_t>(s.bytes.size());
  s.bytes.insert(s.bytes.end(), cd.begin(), cd.end());
  put(s.bytes, 0x06054b50, 4);
  put(s.bytes, 0, 2);
  put(s.bytes, 0, 2);
  put(s.bytes, static_cast<uint32_t>(files.size()), 2);
  put(s.bytes, static_cast<uint32_t>(files.size()), 2);
  put(s.bytes, static_cast<uint32_t>(cd.size()), 4);
  put(s.bytes, cdOffset, 4);
  put(s.bytes, 0, 2);
  return s;
}

// The shape a Readium LCP server emits, namespace attributes included.
std::string encEntry(const char* uri, const char* compression) {
  std::string e =
      "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">"
      "<EncryptionMethod xmlns=\"http://www.w3.org/2001/04/xmlenc#\" "
      "Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"></EncryptionMethod>"
      "<CipherData xmlns=\"http://www.w3.org/2001/04/xmlenc#\">"
      "<CipherReference xmlns=\"http://www.w3.org/2001/04/xmlenc#\" URI=\"";
  e += uri;
  e += "\"></CipherReference></CipherData>";
  if (compression) {
    e += "<EncryptionProperties><EncryptionProperty><Compression "
         "xmlns=\"http://www.idpf.org/2016/encryption#compression\" ";
    e += compression;
    e += "></Compression></EncryptionProperty></EncryptionProperties>";
  }
  return e + "</EncryptedData>";
}

// Identity "cipher": decryption copies, so the test controls the plaintext.
struct CopyCrypto : freeink::content::Crypto {
  int32_t rsaPrivateRaw(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t) override { return -1; }
  bool aes128CbcDecrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, uint8_t*) override { return false; }
  bool aes256CbcDecrypt(const uint8_t*, const uint8_t*, const uint8_t* in, size_t len, uint8_t* out) override {
    std::memmove(out, in, len);
    return true;
  }
  void sha1(const uint8_t*, size_t, uint8_t*) override {}
  void sha256(const uint8_t*, size_t, uint8_t*) override {}
  bool rsaGenerate(freeink::content::RsaKeyPairDer*) override { return false; }
  bool rsaPublicEncrypt(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*) override {
    return false;
  }
  bool rsaPrivateSignRaw(const uint8_t*, size_t, const uint8_t*, uint8_t*) override { return false; }
  bool aes128CbcEncrypt(const uint8_t*, const uint8_t*, const uint8_t*, size_t, uint8_t*) override { return false; }
  bool pkcs12Extract(const uint8_t*, size_t, const std::string&, std::vector<uint8_t>*,
                     std::vector<uint8_t>*) override {
    return false;
  }
  void randomBytes(uint8_t*, size_t) override {}
};

// The host window hooks: one lent window, pairing checked.
static uint8_t g_window[32768];
static int g_windowHeld = 0;
static int g_windowLends = 0;
extern "C" uint8_t* freeink_content_acquire_inflate_window(size_t size) {
  if (g_windowHeld || size > sizeof(g_window)) return nullptr;
  g_windowHeld = 1;
  g_windowLends++;
  return g_window;
}
extern "C" void freeink_content_release_inflate_window(uint8_t* window) {
  assert(window == g_window && g_windowHeld == 1);
  g_windowHeld = 0;
}

// Raw deflate made of stored blocks: no back-references, but the output runs
// past the 32KB window several times.
std::string storedDeflate(const std::string& data) {
  std::string out;
  size_t pos = 0;
  do {
    const size_t n = std::min<size_t>(65535, data.size() - pos);
    const bool final = pos + n == data.size();
    out += static_cast<char>(final ? 1 : 0);
    out += static_cast<char>(n & 0xff);
    out += static_cast<char>(n >> 8);
    out += static_cast<char>(~n & 0xff);
    out += static_cast<char>((~n >> 8) & 0xff);
    out.append(data, pos, n);
    pos += n;
  } while (pos < data.size());
  return out;
}

// IV + body + PKCS#7 padding, under the identity cipher above.
std::string sealed(const std::string& body) {
  std::string out(16, '\0');
  out += body;
  const size_t pad = 16 - body.size() % 16;
  out.append(pad, static_cast<char>(pad));
  return out;
}

bool collect(void* ctx, const uint8_t* data, size_t size) {
  assert(size > 0 && size <= 4096);
  static_cast<std::string*>(ctx)->append(reinterpret_cast<const char*>(data), size);
  return true;
}

void testInflatedEntry() {
  std::string text;
  for (int i = 0; text.size() < 100000; i++) text += "line " + std::to_string(i) + " of the chapter\n";
  const std::string xml =
      "<?xml version=\"1.0\"?><encryption xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" +
      encEntry("text/big.xhtml", "Method=\"8\" OriginalLength=\"100000\"") + "</encryption>";
  auto src = storedZip({{"mimetype", "application/epub+zip"},
                        {"META-INF/encryption.xml", xml},
                        {"text/big.xhtml", sealed(storedDeflate(text))}});
  ProtectedBook book;
  assert(book.open(src));
  const uint8_t key[32] = {0};
  book.setContentKey(key, sizeof(key));
  CopyCrypto crypto;
  std::string out;
  assert(book.decryptEntryToSink(src, crypto, "text/big.xhtml", collect, &out));
  assert(out == text);
  assert(g_windowLends == 1 && g_windowHeld == 0);

  // Truncated deflate: fails, and the window still comes back.
  std::string cut = storedDeflate(text);
  cut.resize(cut.size() - 100);
  auto bad = storedZip(
      {{"mimetype", "application/epub+zip"}, {"META-INF/encryption.xml", xml}, {"text/big.xhtml", sealed(cut)}});
  ProtectedBook badBook;
  assert(badBook.open(bad));
  badBook.setContentKey(key, sizeof(key));
  out.clear();
  assert(!badBook.decryptEntryToSink(bad, crypto, "text/big.xhtml", collect, &out));
  assert(g_windowHeld == 0);
}

// Past the 256-entry reservation the hash tables grow (behind a probe) and the
// lookups still see every entry.
void testLargeManifest() {
  std::string xml = "<?xml version=\"1.0\"?><encryption xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">";
  for (int i = 0; i < 600; i++) {
    const std::string uri = "text/p" + std::to_string(i) + ".xhtml";
    xml += encEntry(uri.c_str(), i % 2 ? "Method=\"0\" OriginalLength=\"5\"" : "Method=\"8\" OriginalLength=\"9\"");
  }
  xml += "</encryption>";
  auto src = storedZip({{"mimetype", "application/epub+zip"}, {"META-INF/encryption.xml", xml}});
  ProtectedBook book;
  assert(book.open(src));
  assert(book.isEncrypted("text/p0.xhtml") && book.isEncrypted("text/p599.xhtml"));
  assert(book.decryptedSize("text/p598.xhtml") == 9);
  assert(book.decryptedSize("text/p599.xhtml") == 5);
}

// A tag longer than the attribute scratch is refused, not grown into.
void testOversizedTag() {
  const std::string uri = "text/" + std::string(2000, 'a') + ".xhtml";
  const std::string xml =
      "<?xml version=\"1.0\"?><encryption xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" +
      encEntry(uri.c_str(), nullptr) + "</encryption>";
  auto src = storedZip({{"mimetype", "application/epub+zip"}, {"META-INF/encryption.xml", xml}});
  ProtectedBook book;
  assert(!book.open(src));
}

int main() {
  testInflatedEntry();
  testLargeManifest();
  testOversizedTag();

  const std::string xml =
      "<?xml version=\"1.0\"?><encryption xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" +
      encEntry("text/a.xhtml", "Method=\"8\" OriginalLength=\"7175\"") +
      encEntry("text/b.xhtml", "Method=\"0\" OriginalLength=\"20\"") + encEntry("text/c.xhtml", nullptr) +
      "</encryption>";
  auto src = storedZip({{"mimetype", "application/epub+zip"},
                        {"META-INF/encryption.xml", xml},
                        {"text/a.xhtml", std::string(48, 'x')},
                        {"text/b.xhtml", std::string(48, 'y')},
                        {"text/c.xhtml", std::string(32, 'z')}});

  ProtectedBook book;
  assert(book.open(src));
  assert(book.isProtected());
  assert(book.isEncrypted("text/a.xhtml") && book.isEncrypted("text/c.xhtml"));
  assert(book.decryptedSize("text/a.xhtml") == 7175);  // deflated: OriginalLength
  assert(book.decryptedSize("text/b.xhtml") == 20);    // stored: OriginalLength, not 48
  assert(book.decryptedSize("text/c.xhtml") == 32);    // no property: zip size fallback
  assert(book.decryptedSize("mimetype") == 20);
  assert(book.decryptedSize("missing") == 0);

  std::puts("test_protected: all assertions passed");
  return 0;
}
