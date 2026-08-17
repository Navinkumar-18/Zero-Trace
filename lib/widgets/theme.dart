import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  // Figma Design System Palette: Zero Trace
  static const Color bgDark = Color(0xFFF6F8FB);        // Page background (#f6f8fb)
  static const Color surfaceDark = Color(0xFFFFFFFF);    // Card/panel surface (#ffffff)
  static const Color surfaceCard = Color(0xFFEFF3F6);    // Inset container background (#eff3f6)
  static const Color surfaceBorder = Color(0xFFDBE1E8);  // Borders & dividers (#dbe1e8)

  static const Color accentEmerald = Color(0xFF0F9360);   // Primary brand green (#0f9360)
  static const Color accentEmeraldLight = Color(0xFFE0F4ED); // Emerald badge fill (#e0f4ed)
  static const Color accentEmeraldDark = Color(0xFF193F33);  // Dark green container (#193f33)
  
  static const Color accentGold = Color(0xFFDB8414);     // Warm amber warning/queued (#db8414)
  static const Color accentGoldLight = Color(0xFFFEF3C7);
  static const Color accentBlue = Color(0xFF2563EB);     
  static const Color accentRose = Color(0xFFD11E28);     // Destructive red (#d11e28)
  static const Color accentOrange = Color(0xFFEA580C);

  static const Color textPrimary = Color(0xFF131923);    // Primary dark charcoal (#131923)
  static const Color textSecondary = Color(0xFF606D7F);  // Slate gray text (#606d7f)
  static const Color textMuted = Color(0xFF94A3B8);      // Muted gray

  // Code/log area colors (dark inset panels for contrast)
  static const Color codeBackground = Color(0xFF1E293B);
  static const Color codeText = Color(0xFFE2E8F0);

  static ThemeData get darkTheme => lightTheme; // Alias for backwards compat

  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      scaffoldBackgroundColor: bgDark,
      colorScheme: const ColorScheme.light(
        primary: accentEmerald,
        onPrimary: Colors.white,
        secondary: accentBlue,
        onSecondary: Colors.white,
        surface: surfaceDark,
        onSurface: textPrimary,
        error: accentRose,
        onError: Colors.white,
      ),
      cardTheme: CardThemeData(
        color: surfaceDark,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: surfaceBorder, width: 1),
        ),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: surfaceDark,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        titleTextStyle: GoogleFonts.inter(
          color: textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
        ),
        iconTheme: const IconThemeData(color: textPrimary),
      ),
      textTheme: TextTheme(
        displayLarge: GoogleFonts.inter(color: textPrimary, fontSize: 32, fontWeight: FontWeight.bold),
        titleLarge: GoogleFonts.inter(color: textPrimary, fontSize: 22, fontWeight: FontWeight.w600),
        titleMedium: GoogleFonts.inter(color: textPrimary, fontSize: 16, fontWeight: FontWeight.w600),
        bodyLarge: GoogleFonts.inter(color: textPrimary, fontSize: 16),
        bodyMedium: GoogleFonts.inter(color: textSecondary, fontSize: 14),
        bodySmall: GoogleFonts.inter(color: textMuted, fontSize: 12),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: accentEmerald,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
          textStyle: GoogleFonts.inter(
            fontWeight: FontWeight.w700,
            fontSize: 14,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: accentGold,
          side: const BorderSide(color: accentGold, width: 1.5),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: GoogleFonts.outfit(
            fontWeight: FontWeight.w600,
            fontSize: 14,
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surfaceCard,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: surfaceBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: surfaceBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: accentGold, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        labelStyle: const TextStyle(color: textSecondary),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: surfaceDark,
        selectedIconTheme: const IconThemeData(color: accentGold, size: 24),
        unselectedIconTheme: const IconThemeData(color: textMuted, size: 22),
        selectedLabelTextStyle: GoogleFonts.outfit(
          color: accentGold,
          fontSize: 12,
          fontWeight: FontWeight.w700,
        ),
        unselectedLabelTextStyle: GoogleFonts.outfit(
          color: textMuted,
          fontSize: 11,
          fontWeight: FontWeight.w500,
        ),
        indicatorColor: accentGold.withValues(alpha: 0.15),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: surfaceCard,
        side: const BorderSide(color: surfaceBorder),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        labelStyle: GoogleFonts.inter(fontSize: 12, color: textSecondary),
      ),
      dividerTheme: const DividerThemeData(
        color: surfaceBorder,
        thickness: 1,
      ),
      tooltipTheme: TooltipThemeData(
        decoration: BoxDecoration(
          color: codeBackground,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: surfaceBorder),
        ),
        textStyle: GoogleFonts.inter(color: codeText, fontSize: 12),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return accentGold;
          return textMuted;
        }),
        trackColor: WidgetStateProperty.resolveWith((states) {
          if (states.contains(WidgetState.selected)) return accentGold.withValues(alpha: 0.3);
          return surfaceBorder;
        }),
      ),
    );
  }
}
