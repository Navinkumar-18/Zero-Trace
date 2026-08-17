import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../widgets/theme.dart';

/// Main application shell with responsive sidebar navigation.
/// Provides the primary navigation structure for Zero Trace 2.0.
class AppShell extends StatefulWidget {
  final Widget child;
  const AppShell({super.key, required this.child});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  bool _isSidebarExpanded = true;

  static const List<_NavDestination> _destinations = [
    _NavDestination(
      icon: Icons.dashboard_outlined,
      selectedIcon: Icons.dashboard,
      label: 'Dashboard',
      route: '/dashboard',
    ),
    _NavDestination(
      icon: Icons.dns_outlined,
      selectedIcon: Icons.dns,
      label: 'Devices',
      route: '/devices',
    ),
    _NavDestination(
      icon: Icons.cleaning_services_outlined,
      selectedIcon: Icons.cleaning_services,
      label: 'Sanitize',
      route: '/sanitize',
    ),
    _NavDestination(
      icon: Icons.verified_user_outlined,
      selectedIcon: Icons.verified_user,
      label: 'Verification',
      route: '/verification',
    ),
    _NavDestination(
      icon: Icons.description_outlined,
      selectedIcon: Icons.description,
      label: 'Certificates',
      route: '/certificates',
    ),
    _NavDestination(
      icon: Icons.psychology_outlined,
      selectedIcon: Icons.psychology,
      label: 'AI Assistant',
      route: '/ai-assistant',
    ),
    _NavDestination(
      icon: Icons.science_outlined,
      selectedIcon: Icons.science,
      label: 'Research',
      route: '/research',
    ),
    _NavDestination(
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings,
      label: 'Settings',
      route: '/settings',
    ),
  ];

  int _getSelectedIndex(BuildContext context) {
    final location = GoRouterState.of(context).uri.toString();
    for (int i = 0; i < _destinations.length; i++) {
      if (location.startsWith(_destinations[i].route)) return i;
    }
    return 0;
  }

  void _onDestinationSelected(int index) {
    context.go(_destinations[index].route);
  }

  @override
  Widget build(BuildContext context) {
    final selectedIndex = _getSelectedIndex(context);
    final screenWidth = MediaQuery.of(context).size.width;
    final isCompact = screenWidth < 800;

    if (isCompact) {
      // Mobile/narrow: use bottom navigation
      return Scaffold(
        body: widget.child,
        bottomNavigationBar: _buildBottomNav(selectedIndex),
      );
    }

    // Desktop: use sidebar
    return Scaffold(
      body: Row(
        children: [
          // Sidebar
          AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            curve: Curves.easeInOut,
            width: _isSidebarExpanded ? 240 : 72,
            decoration: BoxDecoration(
              color: AppTheme.surfaceDark,
              border: Border(
                right: BorderSide(
                  color: AppTheme.surfaceBorder.withValues(alpha: 0.5),
                ),
              ),
            ),
            child: Column(
              children: [
                // Header
                _buildSidebarHeader(),
                const Divider(height: 1, color: AppTheme.surfaceBorder),

                // Navigation items
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    children: [
                      for (int i = 0; i < _destinations.length; i++)
                        _buildNavItem(i, selectedIndex),
                    ],
                  ),
                ),

                // Demo mode banner
                _buildDemoModeBanner(),

                // Collapse toggle
                const Divider(height: 1, color: AppTheme.surfaceBorder),
                _buildCollapseToggle(),
              ],
            ),
          ),

          // Main content
          Expanded(child: widget.child),
        ],
      ),
    );
  }

  Widget _buildSidebarHeader() {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      padding: EdgeInsets.symmetric(
        horizontal: _isSidebarExpanded ? 20 : 12,
        vertical: 20,
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [AppTheme.accentGold, AppTheme.accentGoldLight],
              ),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.shield, color: Colors.white, size: 20),
          ),
          if (_isSidebarExpanded) ...[
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'ZERO TRACE',
                    style: GoogleFonts.outfit(
                      color: AppTheme.textPrimary,
                      fontSize: 16,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.5,
                    ),
                  ),
                  Text(
                    'v2.0 — SIH25070',
                    style: GoogleFonts.inter(
                      color: AppTheme.textMuted,
                      fontSize: 10,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildNavItem(int index, int selectedIndex) {
    final dest = _destinations[index];
    final isSelected = index == selectedIndex;

    return Padding(
      padding: EdgeInsets.symmetric(
        horizontal: _isSidebarExpanded ? 12 : 8,
        vertical: 2,
      ),
      child: Material(
        color: Colors.transparent,
        borderRadius: BorderRadius.circular(12),
        child: InkWell(
          onTap: () => _onDestinationSelected(index),
          borderRadius: BorderRadius.circular(12),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            padding: EdgeInsets.symmetric(
              horizontal: _isSidebarExpanded ? 14 : 0,
              vertical: 12,
            ),
            decoration: BoxDecoration(
              color: isSelected
                  ? AppTheme.accentGold.withValues(alpha: 0.12)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(12),
              border: isSelected
                  ? Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3))
                  : null,
            ),
            child: Row(
              mainAxisAlignment: _isSidebarExpanded
                  ? MainAxisAlignment.start
                  : MainAxisAlignment.center,
              children: [
                Icon(
                  isSelected ? dest.selectedIcon : dest.icon,
                  color: isSelected ? AppTheme.accentGold : AppTheme.textMuted,
                  size: 22,
                ),
                if (_isSidebarExpanded) ...[
                  const SizedBox(width: 14),
                  Flexible(
                    child: Text(
                      dest.label,
                      style: GoogleFonts.outfit(
                        color: isSelected
                            ? AppTheme.accentGold
                            : AppTheme.textSecondary,
                        fontSize: 14,
                        fontWeight:
                            isSelected ? FontWeight.w700 : FontWeight.w500,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDemoModeBanner() {
    if (!_isSidebarExpanded) {
      return Padding(
        padding: const EdgeInsets.all(8.0),
        child: Tooltip(
          message: 'DEMO MODE — No physical data will be destroyed',
          child: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: AppTheme.accentGold.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3)),
            ),
            child: const Icon(Icons.science, color: AppTheme.accentGold, size: 18),
          ),
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTheme.accentGold.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.25)),
        ),
        child: Row(
          children: [
            const Icon(Icons.science, color: AppTheme.accentGold, size: 16),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                'DEMO MODE\nNo physical data will be destroyed',
                style: GoogleFonts.inter(
                  color: AppTheme.accentGold,
                  fontSize: 10,
                  fontWeight: FontWeight.w600,
                  height: 1.3,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCollapseToggle() {
    return InkWell(
      onTap: () => setState(() => _isSidebarExpanded = !_isSidebarExpanded),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          mainAxisAlignment: _isSidebarExpanded
              ? MainAxisAlignment.end
              : MainAxisAlignment.center,
          children: [
            Icon(
              _isSidebarExpanded
                  ? Icons.chevron_left
                  : Icons.chevron_right,
              color: AppTheme.textMuted,
              size: 20,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBottomNav(int selectedIndex) {
    // Show only the first 5 destinations in bottom nav for space
    final bottomDests = _destinations.take(5).toList();
    return Container(
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(
          top: BorderSide(
            color: AppTheme.surfaceBorder.withValues(alpha: 0.5),
          ),
        ),
      ),
      child: NavigationBar(
        backgroundColor: AppTheme.surfaceDark,
        selectedIndex: selectedIndex < 5 ? selectedIndex : 0,
        indicatorColor: AppTheme.accentGold.withValues(alpha: 0.15),
        onDestinationSelected: _onDestinationSelected,
        destinations: bottomDests
            .map((d) => NavigationDestination(
                  icon: Icon(d.icon, color: AppTheme.textMuted),
                  selectedIcon: Icon(d.selectedIcon, color: AppTheme.accentGold),
                  label: d.label,
                ))
            .toList(),
      ),
    );
  }
}

class _NavDestination {
  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final String route;

  const _NavDestination({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.route,
  });
}
