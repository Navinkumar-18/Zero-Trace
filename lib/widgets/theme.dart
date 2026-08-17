import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  // Brand Palette: Light Executive
  // NOTE: These names are kept for compatibility with all existing screens.
  // The values are light-mode colors.
  static const Color bgDark = Color(0xFFF1F5F9);        // Page background
  static const Color surfaceDark = Color(0xFFFFFFFF);    // Card/panel surface
  static const Color surfaceCard = Color(0xFFF8FAFC);    // Nested card surface
  static const Color surfaceBorder = Color(0xFFE2E8F0);  // Borders & dividers

  static const Color accentGold = Color(0xFFD97706);     // Slightly deeper gold for light bg contrast
  static const Color accentGoldLight = Color(0xFFF59E0B);
  static const Color accentBlue = Color(0xFF0284C7);     // Deeper blue for readability
  static const Color accentEmerald = Color(0xFF059669);   // Deeper emerald
  static const Color accentRose = Color(0xFFE11D48);
  static const Color accentOrange = Color(0xFFEA580C);

  static const Color textPrimary = Color(0xFF0F172A);    // Near-black text
  static const Color textSecondary = Color(0xFF475569);  // Medium gray
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
        primary: accentGold,
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
        titleTextStyle: GoogleFonts.outfit(
          color: textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.5,
        ),
        iconTheme: const IconThemeData(color: textPrimary),
      ),
      textTheme: TextTheme(
        displayLarge: GoogleFonts.outfit(color: textPrimary, fontSize: 32, fontWeight: FontWeight.bold),
        titleLarge: GoogleFonts.outfit(color: textPrimary, fontSize: 22, fontWeight: FontWeight.w600),
        titleMedium: GoogleFonts.outfit(color: textPrimary, fontSize: 16, fontWeight: FontWeight.w600),
        bodyLarge: GoogleFonts.inter(color: textPrimary, fontSize: 16),
        bodyMedium: GoogleFonts.inter(color: textSecondary, fontSize: 14),
        bodySmall: GoogleFonts.inter(color: textMuted, fontSize: 12),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: accentGold,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: GoogleFonts.outfit(
            fontWeight: FontWeight.w700,
            fontSize: 15,
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
