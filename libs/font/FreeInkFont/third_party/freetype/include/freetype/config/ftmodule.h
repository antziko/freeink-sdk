/* FreeInkFont curated module list: TrueType (+GX variations) via sfnt, the
 * smooth (anti-aliased) renderer, and psnames always; the classic B/W raster
 * and the auto-hinter are opt-in (FREEINK_FONT_ENABLE_MONOCHROME /
 * FREEINK_FONT_ENABLE_AUTOHINT) since most consumers render grayscale-AA only
 * and never need FT_LOAD_FORCE_AUTOHINT to actually hint anything. No
 * CFF/Type1/BDF/etc. */
FT_USE_MODULE( FT_Module_Class, psnames_module_class )
FT_USE_MODULE( FT_Module_Class, sfnt_module_class )
FT_USE_MODULE( FT_Driver_ClassRec, tt_driver_class )
FT_USE_MODULE( FT_Renderer_Class, ft_smooth_renderer_class )
#if FREEINK_FONT_ENABLE_MONOCHROME
FT_USE_MODULE( FT_Renderer_Class, ft_raster1_renderer_class )
#endif
#if FREEINK_FONT_ENABLE_AUTOHINT
FT_USE_MODULE( FT_Module_Class, autofit_module_class )
#endif
