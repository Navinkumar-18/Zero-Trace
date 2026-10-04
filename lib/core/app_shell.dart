import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../../widgets/theme.dart';

import '../widgets/sanitization_active_banner.dart';

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
      route: '/advanced/dashboard',
    ),
    _NavDestination(
      icon: Icons.dns_outlined,
      selectedIcon: Icons.dns,
      label: 'Devices',
      route: '/advanced/devices',
    ),
    _NavDestination(
      icon: Icons.cleaning_services_outlined,
      selectedIcon: Icons.cleaning_services,
      label: 'Sanitize',
      route: '/advanced/sanitize',
    ),
    _NavDestination(
      icon: Icons.verified_user_outlined,
      selectedIcon: Icons.verified_user,
      label: 'Verification',
      route: '/advanced/verification',
    ),
    _NavDestination(
      icon: Icons.description_outlined,
      selectedIcon: Icons.description,
      label: 'Certificates',
      route: '/advanced/certificates',
    ),
    _NavDestination(
      icon: Icons.psychology_outlined,
      selectedIcon: Icons.psychology,
      label: 'AI Assistant',
      route: '/advanced/ai',
    ),
    _NavDestination(
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings,
      label: 'Settings',
      route: '/advanced/settings',
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
    final route = _destinations[index].route;
    final controller = context.read<SanitizationController>();

    if (controller.isJobRunning && (route == '/devices' || route == '/sanitize')) {
      final deviceName = controller.currentJob?.device.name ?? 'Target Device';
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: AppTheme.surfaceCard,
          title: const Row(
            children: [
              Icon(Icons.lock, color: AppTheme.accentOrange, size: 22),
              SizedBox(width: 8),
              Text('Sanitization Active', style: TextStyle(color: AppTheme.textPrimary)),
            ],
          ),
          content: Text(
            'Sanitization is currently executing on $deviceName.\n\nSelecting a new device or configuring another workflow is restricted while a job is running.',
            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('DISMISS', style: TextStyle(color: AppTheme.textMuted)),
            ),
            ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.accentOrange,
                foregroundColor: Colors.white,
              ),
              icon: const Icon(Icons.show_chart, size: 16),
              label: const Text('VIEW PROGRESS'),
              onPressed: () {
                Navigator.of(ctx).pop();
                context.go('/sanitize/progress');
              },
            ),
          ],
        ),
      );
      return;
    }

    context.go(route);
  }

  @override
  Widget build(BuildContext context) {
    final selectedIndex = _getSelectedIndex(context);
    final screenWidth = MediaQuery.of(context).size.width;
    final isCompact = screenWidth < 800;
    final controller = context.watch<SanitizationController>();

    if (isCompact) {
      // Mobile/narrow: use bottom navigation
      return Scaffold(
        body: Column(
          children: [
            if (!controller.isRealMode) _buildDemoModeBanner(controller),
            const SanitizationActiveBanner(),
            Expanded(child: widget.child),
          ],
        ),
        bottomNavigationBar: _buildBottomNav(selectedIndex),
      );
    }

    // Desktop: use sidebar
    return Scaffold(
      body: Column(
        children: [
          if (!controller.isRealMode) _buildDemoModeBanner(controller),
          const SanitizationActiveBanner(),
          Expanded(
            child: Row(
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

                      // Mode banner
                      _buildModeStatusBanner(context),

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
          ),
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
              color: AppTheme.accentEmeraldLight,
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Icon(Icons.shield, color: AppTheme.accentEmerald, size: 20),
          ),
          if (_isSidebarExpanded) ...[
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'ZERO TRACE',
                    style: GoogleFonts.inter(
                      color: AppTheme.textPrimary,
                      fontSize: 16,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.5,
                    ),
                  ),
                  Text(
                    'SECURE SANITIZATION',
                    style: GoogleFonts.inter(
                      color: AppTheme.accentEmerald,
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.8,
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
        borderRadius: BorderRadius.circular(10),
        child: InkWell(
          onTap: () => _onDestinationSelected(index),
          borderRadius: BorderRadius.circular(10),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 150),
            padding: EdgeInsets.symmetric(
              horizontal: _isSidebarExpanded ? 14 : 0,
              vertical: 10,
            ),
            decoration: BoxDecoration(
              color: isSelected
                  ? AppTheme.surfaceCard
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              mainAxisAlignment: _isSidebarExpanded
                  ? MainAxisAlignment.start
                  : MainAxisAlignment.center,
              children: [
                Icon(
                  isSelected ? dest.selectedIcon : dest.icon,
                  color: isSelected ? AppTheme.accentEmerald : AppTheme.textSecondary,
                  size: 20,
                ),
                if (_isSidebarExpanded) ...[
                  const SizedBox(width: 12),
                  Flexible(
                    child: Text(
                      dest.label,
                      style: GoogleFonts.inter(
                        color: isSelected
                            ? AppTheme.textPrimary
                            : AppTheme.textSecondary,
                        fontSize: 13,
                        fontWeight:
                            isSelected ? FontWeight.w600 : FontWeight.w500,
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

  Widget _buildModeStatusBanner(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final isRealMode = controller.isRealMode;

    final badgeColor = isRealMode ? AppTheme.accentEmerald : AppTheme.accentGold;
    final badgeIcon = isRealMode ? Icons.memory : Icons.science;
    final badgeTitle = isRealMode ? 'REAL HARDWARE MODE' : 'DEMO MODE';
    final badgeSubtitle = isRealMode
        ? 'Live disk scanner active (lsblk)'
        : 'No physical data will be destroyed';

    if (!_isSidebarExpanded) {
      return Padding(
        padding: const EdgeInsets.all(8.0),
        child: Tooltip(
          message: '$badgeTitle — $badgeSubtitle',
          child: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: badgeColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: badgeColor.withValues(alpha: 0.3)),
            ),
            child: Icon(badgeIcon, color: badgeColor, size: 18),
          ),
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: badgeColor.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: badgeColor.withValues(alpha: 0.25)),
        ),
        child: Row(
          children: [
            Icon(badgeIcon, color: badgeColor, size: 16),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                '$badgeTitle\n$badgeSubtitle',
                style: GoogleFonts.inter(
                  color: badgeColor,
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
  Widget _buildDemoModeBanner(SanitizationController controller) {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: AppTheme.accentGold.withValues(alpha: 0.15),
        border: Border(
          bottom: BorderSide(
            color: AppTheme.accentGold.withValues(alpha: 0.5),
            width: 1.5,
          ),
        ),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: SafeArea(
        bottom: false,
        child: Row(
          children: [
            const Icon(Icons.science, color: AppTheme.accentGold, size: 18),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                '⚠ DEMO / SIMULATED MODE — No physical data will be destroyed',
                style: GoogleFonts.inter(
                  color: AppTheme.accentGold,
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                ),
              ),
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
