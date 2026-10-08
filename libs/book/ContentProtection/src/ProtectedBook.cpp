#include "ProtectedBook.h"

#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <new>
#include <utility>

#include "ContentMinizConfig.h"
#include "Util.h"

namespace freeink {
namespace content {

namespace {
constexpr const char* kEncryptionXml = "META-INF/encryption.xml";

bool tagHas(const char* tag, size_t len, const char* token) {
  const size_t tlen = strlen(token);
  if (tlen > len) return false;
  for (size_t i = 0; i + tlen <= len; i++) {
    if (memcmp(tag + i, token, tlen) == 0) return true;
  }
  return false;
}

// Extract one attribute value from a raw tag slice ('<' .. '>'). Requires
// whitespace before the name so URI= cannot match inside another attribute.
// These manifests are machine-generated with quoted attributes; both quote
// styles accepted.
bool tagAttr(const char* tag, size_t len, const char* attr, std::string* out) {
  const size_t alen = strlen(attr);
  for (size_t i = 1; i + alen + 2 < len; i++) {
    if (memcmp(tag + i, attr, alen) != 0 || tag[i + alen] != '=') continue;
    const char before = tag[i - 1];
    if (before != ' ' && before != '\t' && before != '\r' && before != '\n') continue;
    const char quote = tag[i + alen + 1];
    if (quote != '"' && quote != '\'') continue;
    const char* start = tag + i + alen + 2;
    const char* end = static_cast<const char*>(memchr(start, quote, len - (start - tag)));
    if (!end) return false;
    out->assign(start, static_cast<size_t>(end - start));
    return true;
  }
  return false;
}

// Raw-deflate decoder with the state and the 32KB window in separate blocks
// (mz_inflateInit2 wants both in one ~41KB block), the window borrowed from
// the host when it lends one.
class RawInflater {
 public:
  static constexpr size_t kWindow = TINFL_LZ_DICT_SIZE;
  // Output is handed to the sink in slices of at most this size.
  static constexpr size_t kEmitSlice = 4096;

  RawInflater() = default;
  RawInflater(const RawInflater&) = delete;
  RawInflater& operator=(const RawInflater&) = delete;
  ~RawInflater() {
    free(state_);
    if (borrowed_) {
      freeink_content_release_inflate_window(window_);
    } else {
      free(window_);
    }
  }

  bool init() {
    state_ = static_cast<tinfl_decompressor*>(malloc(sizeof(tinfl_decompressor)));
    if (!state_) return false;
    if (freeink_content_acquire_inflate_window) {
      window_ = freeink_content_acquire_inflate_window(kWindow);
      borrowed_ = window_ != nullptr;
    }
    if (!window_) window_ = static_cast<uint8_t*>(malloc(kWindow));
    if (!window_) return false;
    tinfl_init(state_);
    return true;
  }

  bool done() const { return done_; }

  // Decodes one input chunk; `last` marks the end of the compressed input.
  // Returns false on corrupt input or when emit refuses output.
  template <typename Emit>
  bool feed(const uint8_t* in, size_t len, bool last, Emit&& emit) {
    while (!done_) {
      size_t inSize = len;
      size_t outSize = kWindow - pos_;
      const tinfl_status status = tinfl_decompress(state_, in, &inSize, window_, window_ + pos_, &outSize,
                                                   last ? 0 : TINFL_FLAG_HAS_MORE_INPUT);
      in += inSize;
      len -= inSize;
      for (size_t off = 0; off < outSize; off += kEmitSlice) {
        const size_t n = outSize - off < kEmitSlice ? outSize - off : kEmitSlice;
        if (!emit(window_ + pos_ + off, n)) return false;
      }
      pos_ = (pos_ + outSize) & (kWindow - 1);
      if (status == TINFL_STATUS_DONE) {
        done_ = true;
      } else if (status < 0) {
        return false;
      } else if (status == TINFL_STATUS_NEEDS_MORE_INPUT && len == 0) {
        return true;
      } else if (inSize == 0 && outSize == 0) {
        return false;
      }
    }
    return true;
  }

 private:
  tinfl_decompressor* state_ = nullptr;
  uint8_t* window_ = nullptr;
  bool borrowed_ = false;
  size_t pos_ = 0;
  bool done_ = false;
};
}  // namespace

void ProtectedBook::reserveErrorBuffer() {
  if (heapProbe(96)) lastError_.reserve(64);
  lastError_.clear();
}

bool ProtectedBook::open(ByteSource& source) {
  reserveErrorBuffer();
  protected_ = false;

  if (!zip_.open(source)) {
    lastError_ = "not a zip container";
    return false;
  }

  return finishOpen(source);
}

bool ProtectedBook::openFromScan(ByteSource& source, ZipScan&& scan) {
  reserveErrorBuffer();
  protected_ = false;
  zip_ = std::move(scan);
  return finishOpen(source);
}

bool ProtectedBook::finishOpen(ByteSource& source) {
  const ZipEntryInfo* encEntry = zip_.find(kEncryptionXml);
  if (!encEntry) {
    return true;  // plain EPUB; nothing to do
  }

  // Stream-parse the manifest straight out of the zip: it enumerates every
  // encrypted resource, so its size scales with the container's file count
  // (measured ~60KB for a many-hundred-entry book) and materializing it
  // whole was OOM-aborting small-heap devices at open.
  if (!scanEncryptionXml(source, *encEntry)) {
    if (lastError_.empty()) lastError_ = "failed to read encryption.xml";
    return false;
  }

  // A manifest containing only embedded-font obfuscation needs no content
  // key or alternate read path.
  protected_ = !encryptedUriHashes_.empty();
  return true;
}

void ProtectedBook::setContentKey(const uint8_t* key, size_t len) {
  if (len != 16 && len != 32) return;
  memcpy(bookKey_, key, len);
  keyLen_ = len;
  hasKey_ = true;
}

bool ProtectedBook::isEncrypted(const std::string& name) const {
  return std::binary_search(encryptedUriHashes_.begin(), encryptedUriHashes_.end(),
                            fnv1a64(name.data(), name.size()));
}

size_t ProtectedBook::decryptedSize(const std::string& name) const {
  // The zip records the stored blob (LCP: IV + ciphertext + padding), not the
  // plaintext; encryption.xml's OriginalLength is the real size when given.
  const uint64_t hash = fnv1a64(name.data(), name.size());
  const auto it = std::lower_bound(originalSizes_.begin(), originalSizes_.end(), std::make_pair(hash, uint32_t{0}));
  if (it != originalSizes_.end() && it->first == hash) return it->second;
  const ZipEntryInfo* entry = zip_.find(name);
  return entry ? entry->uncompressedSize : 0;
}

bool ProtectedBook::decryptEntryToSink(ByteSource& source, Crypto& crypto,
                                       const std::string& name, ContentChunkSink sink,
                                       void* context) {
  if (!hasKey_ || keyLen_ != (aes256_ ? 32u : 16u)) {
    lastError_ = "no content key";
    return false;
  }
  const ZipEntryInfo* entry = zip_.find(name);
  if (!entry) {
    // The concat allocates a temporary; fall back to the SSO-sized literal
    // (never allocates) when the heap cannot take it.
    if (heapProbe(name.size() + 48)) {
      lastError_ = "entry not found: " + name;
    } else {
      lastError_ = "entry not found";
    }
    return false;
  }
  if (entry->compressedSize < 32 || (entry->compressedSize - 16) % 16 != 0) {
    lastError_ = "entry size not AES-shaped";
    return false;
  }

  uint64_t offset = 0;
  if (!zip_.dataOffset(source, *entry, &offset)) {
    lastError_ = "entry offset unavailable";
    return false;
  }

  uint8_t iv[16];
  if (source.readAt(offset, iv, sizeof(iv)) != sizeof(iv)) {
    lastError_ = "entry IV read failed";
    return false;
  }

  constexpr size_t kCipherChunk = 2048;

  // LCP marks already-uncompressed resources Compression Method="0":
  // decrypt-only, no inflate stage.
  const bool stored =
      std::binary_search(storedUriHashes_.begin(), storedUriHashes_.end(), fnv1a64(name.data(), name.size()));

  RawInflater inflater;
  if (!stored && !inflater.init()) {
    lastError_ = "insufficient memory for content stream";
    return false;
  }
  std::unique_ptr<uint8_t[]> cipherBuf(new (std::nothrow) uint8_t[kCipherChunk]);
  std::unique_ptr<uint8_t[]> plainBuf(cipherBuf ? new (std::nothrow) uint8_t[kCipherChunk] : nullptr);
  if (!plainBuf) {
    lastError_ = "insufficient memory for content stream";
    return false;
  }
  uint8_t* cipher = cipherBuf.get();
  uint8_t* plain = plainBuf.get();

  // A sink that refuses data (a consumer that has read enough) is told apart
  // from corrupt content in lastError.
  bool sinkStopped = false;
  const auto toSink = [&](const uint8_t* data, size_t size) {
    if (sink && sink(context, data, size)) return true;
    sinkStopped = true;
    return false;
  };
  bool ended = false;
  auto inflateChunk = [&](const uint8_t* data, size_t size, bool last) {
    const bool fed = inflater.feed(data, size, last, toSink);
    ended = inflater.done();
    return fed;
  };

  auto emitChunk = [&](const uint8_t* data, size_t size, bool last) {
    if (!stored) return inflateChunk(data, size, last);
    return size == 0 || toSink(data, size);
  };

  uint32_t remaining = entry->compressedSize - 16;
  offset += 16;
  bool ok = true;
  while (remaining > 0 && !ended) {
    const size_t amount = remaining < kCipherChunk ? remaining : kCipherChunk;
    if (source.readAt(offset, cipher, amount) != static_cast<int32_t>(amount)) {
      ok = false;
      lastError_ = "entry read failed";
      break;
    }
    uint8_t nextIv[16];
    memcpy(nextIv, cipher + amount - sizeof(nextIv), sizeof(nextIv));
    const bool decrypted = aes256_ ? crypto.aes256CbcDecrypt(bookKey_, iv, cipher, amount, plain)
                                   : crypto.aes128CbcDecrypt(bookKey_, iv, cipher, amount, plain);
    if (!decrypted) {
      ok = false;
      lastError_ = "content read failed";
      break;
    }
    memcpy(iv, nextIv, sizeof(iv));

    size_t plainSize = amount;
    if (amount == remaining) {
      const uint8_t pad = plain[plainSize - 1];
      if (pad >= 1 && pad <= 16 && pad <= plainSize) {
        if (aes256_) {
          // W3C xmlenc padding (LCP): the fill bytes are random; only the
          // count byte is meaningful.
          plainSize -= pad;
        } else {
          bool valid = true;
          for (size_t i = plainSize - pad; i < plainSize; i++) valid = valid && plain[i] == pad;
          if (valid) plainSize -= pad;
        }
      }
    }
    if (!emitChunk(plain, plainSize, amount == remaining)) {
      ok = false;
      lastError_ = sinkStopped ? kSinkStoppedError : "inflate failed";
      break;
    }
    offset += amount;
    remaining -= amount;
  }

  if (stored) {
    ended = ok;
  } else if (ok && !ended) {
    ok = false;
    lastError_ = "inflate failed";
  }
  return ok && ended;
}

bool ProtectedBook::scanEncryptionXml(ByteSource& source, const ZipEntryInfo& entry) {
  encryptedUriHashes_.clear();
  storedUriHashes_.clear();
  originalSizes_.clear();
  aes256_ = false;

  uint64_t at = 0;
  if (!zip_.dataOffset(source, entry, &at)) {
    lastError_ = "entry offset unavailable";
    return false;
  }
  if (entry.method != 0 && entry.method != 8) return false;

  constexpr size_t kChunk = 2048;
  auto* bufs = static_cast<uint8_t*>(malloc(kChunk));  // freed below; kept raw for the single free
  if (!bufs) {
    lastError_ = "out of memory";
    return false;
  }
  uint8_t* inBuf = bufs;

  // Tag-level scan. Inter-tag text is discarded; only element attributes
  // matter here. `carry` holds an unterminated tag across chunk boundaries —
  // manifest tags run ~200 bytes, so a tag that never closes within the cap
  // is a malformed document, not a real split.
  std::string carry;
  int pendingCipher = 0;  // bits of the EncryptionMethod just seen; 0 = unsupported
  uint64_t lastHash = 0;
  bool haveLast = false;
  bool malformed = false;
  std::string value;
  // Pre-reserve the bounded worst case behind a nothrow probe: string/vector
  // growth is a throwing allocation, and with -fno-exceptions a failed grow
  // abort()s the firmware mid-open (field crash: bad_alloc in feed()'s append
  // when a book is opened on a fragmented post-session heap). carry peaks at
  // the 4KB unterminated-tag cap plus one chunk; with capacity reserved, the
  // appends below never allocate.
  {
    constexpr size_t kCarryReserve = 4096 + kChunk;
    constexpr size_t kValueReserve = 1024;  // attribute scratch (URIs)
    constexpr size_t kUriReserve = 256;     // encrypted-entry hashes (8B each)
    void* probe = malloc(kCarryReserve + kValueReserve + kUriReserve * sizeof(uint64_t) +
                         kUriReserve * sizeof(std::pair<uint64_t, uint32_t>) + 512);
    if (!probe) {
      free(bufs);
      lastError_ = "out of memory";
      return false;
    }
    free(probe);
    carry.reserve(kCarryReserve);
    value.reserve(kValueReserve);
    encryptedUriHashes_.reserve(kUriReserve);
    originalSizes_.reserve(kUriReserve);
    storedUriHashes_.reserve(64);  // covered by the probe's slack
  }
  // Past the reservation, a vector doubles only behind a probe for the new
  // block (taken while the old one is still held, as the grow needs).
  bool outOfMemory = false;
  auto roomFor = [&](auto& vec) {
    if (vec.size() < vec.capacity()) return true;
    const size_t grown = vec.capacity() < 16 ? 16 : vec.capacity() * 2;
    if (!heapProbe(grown * sizeof(vec[0]))) {
      outOfMemory = true;
      return false;
    }
    vec.reserve(grown);
    return true;
  };
  auto handleTag = [&](const char* tag, size_t len) {
    if (len < 3 || tag[1] == '/' || tag[1] == '?' || tag[1] == '!') return;
    // An attribute value is never longer than its tag; this keeps `value`
    // inside its reservation.
    if (len > value.capacity()) {
      malformed = true;
      return;
    }
    if (tagHas(tag, len, "EncryptionMethod")) {
      pendingCipher = 0;
      if (tagAttr(tag, len, "Algorithm", &value)) {
        if (value.find("aes128-cbc") != std::string::npos) pendingCipher = 128;
        if (value.find("aes256-cbc") != std::string::npos) pendingCipher = 256;
      }
    } else if (tagHas(tag, len, "CipherReference")) {
      if (pendingCipher != 0 && tagAttr(tag, len, "URI", &value) && !value.empty()) {
        lastHash = fnv1a64(value.data(), value.size());
        haveLast = true;
        if (!roomFor(encryptedUriHashes_)) return;
        encryptedUriHashes_.push_back(lastHash);
        if (pendingCipher == 256) aes256_ = true;
      }
      pendingCipher = 0;
    } else if (tagHas(tag, len, "Compression")) {
      // Per-entry compression property (LCP): Method="0" means the plaintext
      // is not deflated. Follows the entry's CipherReference in the manifest.
      if (haveLast && tagAttr(tag, len, "Method", &value) && value == "0") {
        if (!roomFor(storedUriHashes_)) return;
        storedUriHashes_.push_back(lastHash);
      }
      if (haveLast && tagAttr(tag, len, "OriginalLength", &value)) {
        char* end = nullptr;
        const unsigned long n = strtoul(value.c_str(), &end, 10);
        if (end != value.c_str() && *end == '\0' && n <= UINT32_MAX) {
          if (!roomFor(originalSizes_)) return;
          originalSizes_.emplace_back(lastHash, static_cast<uint32_t>(n));
        }
      }
    }
  };
  auto feed = [&](const uint8_t* data, size_t size) -> bool {
    carry.append(reinterpret_cast<const char*>(data), size);
    size_t pos = 0;
    for (;;) {
      const size_t lt = carry.find('<', pos);
      if (lt == std::string::npos) {
        carry.clear();
        return true;
      }
      const size_t gt = carry.find('>', lt);
      if (gt == std::string::npos) {
        carry.erase(0, lt);
        if (carry.size() > 4096) {
          malformed = true;
          return false;
        }
        return true;
      }
      handleTag(carry.data() + lt, gt - lt + 1);
      if (malformed || outOfMemory) return false;
      pos = gt + 1;
    }
  };

  bool ok = true;
  uint32_t remaining = entry.compressedSize;
  if (entry.method == 0) {
    while (remaining > 0 && ok) {
      const size_t amount = remaining < kChunk ? remaining : kChunk;
      ok = source.readAt(at, inBuf, amount) == static_cast<int32_t>(amount) && feed(inBuf, amount);
      at += amount;
      remaining -= static_cast<uint32_t>(amount);
    }
  } else {
    RawInflater inflater;
    if (!inflater.init()) {
      free(bufs);
      lastError_ = "out of memory";
      return false;
    }
    while (remaining > 0 && ok && !inflater.done()) {
      const size_t amount = remaining < kChunk ? remaining : kChunk;
      if (source.readAt(at, inBuf, amount) != static_cast<int32_t>(amount)) {
        ok = false;
        break;
      }
      at += amount;
      remaining -= static_cast<uint32_t>(amount);
      ok = inflater.feed(inBuf, amount, remaining == 0, feed);
    }
    ok = ok && inflater.done();
  }
  free(bufs);

  if (outOfMemory) {
    lastError_ = "encryption manifest too large for memory";
    return false;
  }
  if (!ok || malformed) {
    if (lastError_.empty()) lastError_ = "encryption manifest unreadable";
    return false;
  }
  std::sort(encryptedUriHashes_.begin(), encryptedUriHashes_.end());
  std::sort(storedUriHashes_.begin(), storedUriHashes_.end());
  std::sort(originalSizes_.begin(), originalSizes_.end());
  return true;
}

}  // namespace content
}  // namespace freeink
