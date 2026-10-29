import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:printing/printing.dart';

import '../core/app_paths.dart';
import '../models/untrusted_text.dart';
import '../services/audit_log_service.dart';
import '../services/certificate_service.dart';
import '../widgets/theme.dart';
import 'certificate_dialog.dart';

/// Real operation History, shown inside [SimpleShell].
///
/// Lists the most recent audit-log entries (newest first, max 100) with the
/// hash-chain "integrity check" result. Simulated runs are hidden by default;
/// older unchained entries (no `isSimulated` field) are never mixed with real
/// runs and appear under a separate, collapsed "Legacy entries" section.
class HistoryScreen extends StatefulWidget {
  const HistoryScreen({
    super.key,
    this.auditLogService,
    this.certificateService,
  });

  /// Injectable for tests; production resolves paths via [AppPaths].
  final AuditLogService? auditLogService;
  final CertificateService? certificateService;

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  static const int _maxEntries = 100;

  late final AuditLogService _auditLogService =
      widget.auditLogService ?? AuditLogService(paths: AppPaths.production());
  late final CertificateService _certificateService =
      widget.certificateService ?? CertificateService();

  bool _isLoading = true;
  bool _hideSimulated = true;
  bool _showLegacy = false;
  List<AuditLogEntry> _entries = const [];
  ChainIntegrityResult? _chainResult;
  bool _isVerifyingChain = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    if (mounted) {
      setState(() {
        _isLoading = true;
        _isVerifyingChain = true;
      });
    }

    final entries = await _auditLogService.getEntries(includeSimulated: true);

    if (!mounted) return;
    setState(() {
      _entries = entries;
      _isLoading = false;
    });

    final chainResult = await _auditLogService.verifyChainIntegrity();
    if (!mounted) return;
    setState(() {
      _chainResult = chainResult;
      _isVerifyingChain = false;
    });
  }

  List<AuditLogEntry> get _currentEntries =>
      _entries.where((e) => !e.isLegacy).toList();

  List<AuditLogEntry> get _legacyEntries =>
      _entries.where((e) => e.isLegacy).toList();

  List<AuditLogEntry> get _visibleEntries {
    final list = _currentEntries
        .where((e) => !(_hideSimulated && e.isSimulated))
        .toList();
    return list.length > _maxEntries ? list.sublist(0, _maxEntries) : list;
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _buildHeader(),
        _buildIntegrityRow(),
        _buildFilterBar(),
        Expanded(
          child: _isLoading
              ? const Center(child: CircularProgressIndicator())
              : _buildContent(),
        ),
      ],
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(bottom: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          const Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Operation History',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: AppTheme.textPrimary,
                  ),
                ),
                SizedBox(height: 2),
                Text(
                  'Audit log entries with hash-chain integrity check',
                  style: TextStyle(fontSize: 12, color: AppTheme.textMuted),
                ),
              ],
            ),
          ),
          OutlinedButton.icon(
            icon: const Icon(Icons.download, size: 16),
            label: const Text('Export Log'),
            onPressed: _exportLog,
          ),
          const SizedBox(width: 8),
          IconButton(
            icon: const Icon(Icons.refresh, color: AppTheme.textPrimary),
            tooltip: 'Refresh',
            onPressed: _loadData,
          ),
        ],
      ),
    );
  }

  Widget _buildIntegrityRow() {
    if (_isVerifyingChain) {
      return _integrityBanner(
        key: const Key('history-integrity-verifying'),
        icon: Icons.hourglass_top,
        color: AppTheme.textMuted,
        title: 'Integrity check: verifying...',
        subtitle: 'Computing the SHA-256 hash chain in the background.',
      );
    }
    final result = _chainResult;
    if (result == null) {
      return _integrityBanner(
        key: const Key('history-integrity-unknown'),
        icon: Icons.help_outline,
        color: AppTheme.textMuted,
        title: 'Integrity check: unavailable',
        subtitle: 'The audit log could not be read.',
      );
    }

    switch (result.status) {
      case ChainIntegrityStatus.valid:
        return _integrityBanner(
          key: const Key('history-integrity-valid'),
          icon: Icons.verified_user,
          color: AppTheme.simpleSuccess,
          title: 'Integrity check: valid',
          subtitle:
              '${result.totalEntries} chained entries verified against the genesis hash.',
        );
      case ChainIntegrityStatus.validWithLegacy:
        return _integrityBanner(
          key: const Key('history-integrity-legacy'),
          icon: Icons.verified_user,
          color: AppTheme.accentGold,
          title: 'Integrity check: valid (with legacy entries)',
          subtitle:
              '${result.totalEntries - result.legacyCount} chained entries verified; '
              '${result.legacyCount} older unchained entries tolerated.',
        );
      case ChainIntegrityStatus.broken:
        return _integrityBanner(
          key: const Key('history-integrity-broken'),
          icon: Icons.gpp_maybe,
          color: AppTheme.simpleDestructive,
          title: 'Integrity check: failed at line ${result.brokenLineNumber}',
          subtitle: result.failureReason ?? 'Hash chain mismatch detected.',
        );
    }
  }

  Widget _integrityBanner({
    required Key key,
    required IconData icon,
    required Color color,
    required String title,
    required String subtitle,
  }) {
    return Container(
      key: key,
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        border: const Border(bottom: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color, size: 22),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
                Text(
                  subtitle,
                  style: const TextStyle(
                    fontSize: 11,
                    color: AppTheme.textMuted,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    final legacy = _legacyEntries;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 6),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(bottom: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          Flexible(
            child: Text(
              'Showing ${_visibleEntries.length} of ${_currentEntries.length} entries',
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 12, color: AppTheme.textMuted),
            ),
          ),
          const Spacer(),
          if (legacy.isNotEmpty)
            TextButton.icon(
              key: const Key('history-toggle-legacy'),
              icon: Icon(
                _showLegacy ? Icons.expand_less : Icons.expand_more,
                size: 16,
              ),
              label: Text(
                'Legacy (${legacy.length})',
                style: const TextStyle(fontSize: 12),
              ),
              onPressed: () => setState(() => _showLegacy = !_showLegacy),
            ),
          const SizedBox(width: 4),
          const Text(
            'Hide simulated',
            style: TextStyle(fontSize: 12, color: AppTheme.textPrimary),
          ),
          const SizedBox(width: 6),
          Switch(
            key: const Key('history-toggle-simulated'),
            value: _hideSimulated,
            activeThumbColor: AppTheme.simplePrimary,
            onChanged: (val) => setState(() => _hideSimulated = val),
          ),
        ],
      ),
    );
  }

  Widget _buildContent() {
    if (_currentEntries.isEmpty && _legacyEntries.isEmpty) {
      return _buildEmptyState();
    }
    if (_visibleEntries.isEmpty && !_showLegacy) {
      return _buildEmptyState();
    }

    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemCount: _visibleEntries.length + (_showLegacy ? _legacyEntries.length : 0),
      separatorBuilder: (_, _) => const SizedBox(height: 12),
      itemBuilder: (context, index) {
        if (index < _visibleEntries.length) {
          return _buildEntryCard(_visibleEntries[index]);
        }
        final legacyIndex = index - _visibleEntries.length;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (legacyIndex == 0) _buildLegacyHeader(),
            _buildEntryCard(_legacyEntries[legacyIndex]),
          ],
        );
      },
    );
  }

  Widget _buildLegacyHeader() {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.accentGold.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.4)),
      ),
      child: const Row(
        children: [
          Icon(Icons.help_outline, size: 18, color: AppTheme.accentGold),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              'Legacy entries, source unknown',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                color: AppTheme.textPrimary,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      key: const Key('history-empty'),
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.history, size: 48, color: AppTheme.textMuted),
            const SizedBox(height: 16),
            const Text(
              'No sanitization history',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: AppTheme.textPrimary,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Entries appear here only after a real or simulated sanitization '
              'job runs.${_hideSimulated ? ' Simulated runs are currently hidden.' : ''}',
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 12, color: AppTheme.textMuted),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEntryCard(AuditLogEntry entry) {
    final badge = _OutcomeBadge.of(entry.outcome);
    final deviceName =
        UntrustedText(entry.deviceName ?? 'Unknown device').sanitized;

    return Container(
      key: ValueKey('history-entry-${entry.jobId}'),
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppTheme.surfaceBorder)),
            ),
            child: Row(
              children: [
                Icon(badge.icon, color: badge.color, size: 18),
                const SizedBox(width: 8),
                Text(
                  badge.label,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: badge.color,
                  ),
                ),
                if (entry.isSimulated) ...[
                  const SizedBox(width: 8),
                  _chip('SIMULATED', AppTheme.accentGold),
                ],
                if (entry.isLegacy) ...[
                  const SizedBox(width: 8),
                  _chip('LEGACY', AppTheme.textMuted),
                ],
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    deviceName,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: AppTheme.textPrimary,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  _formatTimestamp(entry.timestamp),
                  style: const TextStyle(
                    fontSize: 11,
                    color: AppTheme.textMuted,
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _field('Scope',
                              entry.scope == 'partial' ? 'Partition wipe' : 'Full disk'),
                          _field('Serial',
                              UntrustedText(entry.deviceSerial).sanitized),
                          _field('Target path',
                              UntrustedText(entry.devicePath).sanitized),
                          _field('Standard', entry.standardReference),
                        ],
                      ),
                    ),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _field('Method', UntrustedText(entry.method).sanitized),
                          _field('Method class', entry.methodClass ?? '—'),
                          _field(
                            'Verification',
                            entry.verificationPassed == null
                                ? '—'
                                : (entry.verificationPassed! ? 'Passed' : 'Failed'),
                          ),
                          _field('Certificate ID', entry.certificateId ?? '—'),
                        ],
                      ),
                    ),
                  ],
                ),
                // P4-fix: a failed run must state its readable engine reason
                // right on the History card.
                if (entry.failureReason != null &&
                    entry.failureReason!.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _field(
                    'Failure',
                    UntrustedText(entry.failureReason!).sanitized,
                  ),
                ],
                if (entry.partitions != null && entry.partitions!.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  const Text(
                    'Target partitions',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                      color: AppTheme.textPrimary,
                    ),
                  ),
                  const SizedBox(height: 4),
                  ...entry.partitions!.map(
                    (p) => Padding(
                      padding: const EdgeInsets.only(left: 6, bottom: 2),
                      child: Text(
                        '• Partition #${p.partitionNumber}: sectors ${p.startSector}–'
                        '${p.startSector + p.sizeSectors} | status: ${p.status} | '
                        'wiped: ${(p.bytesWiped / (1024 * 1024)).toStringAsFixed(1)} MB',
                        style: const TextStyle(
                          fontSize: 11,
                          color: AppTheme.textMuted,
                        ),
                      ),
                    ),
                  ),
                ],
                if (entry.commandLog.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _CommandLog(entry: entry),
                ],
              ],
            ),
          ),
          if (entry.certificateId != null) _buildActions(entry),
        ],
      ),
    );
  }

  Widget _buildActions(AuditLogEntry entry) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          TextButton.icon(
            icon: const Icon(Icons.description, size: 16),
            label: const Text('View certificate / report',
                style: TextStyle(fontSize: 11)),
            onPressed: () => _viewCertificate(entry),
          ),
          TextButton.icon(
            icon: const Icon(Icons.picture_as_pdf, size: 16),
            label: const Text('Export PDF', style: TextStyle(fontSize: 11)),
            onPressed: () => _exportPdf(entry),
          ),
          TextButton.icon(
            icon: const Icon(Icons.data_object, size: 16),
            label: const Text('View raw JSON', style: TextStyle(fontSize: 11)),
            onPressed: () => _viewRawJson(entry),
          ),
        ],
      ),
    );
  }

  Future<void> _viewCertificate(AuditLogEntry entry) async {
    final cert = await _auditLogService.getCertificateById(entry.certificateId!);
    if (!mounted) return;
    if (cert == null) {
      _snack('Certificate file not found on disk.');
      return;
    }
    await SimpleCertificateDialog.show(context, certificate: cert);
  }

  Future<void> _exportPdf(AuditLogEntry entry) async {
    final cert = await _auditLogService.getCertificateById(entry.certificateId!);
    if (!mounted) return;
    if (cert == null) {
      _snack('Certificate file not found on disk.');
      return;
    }
    try {
      final bytes = await _certificateService.generatePdfBytes(cert);
      await Printing.sharePdf(bytes: bytes, filename: '${cert.certificateId}.pdf');
    } catch (e) {
      _snack('Export failed: $e');
    }
  }

  void _viewRawJson(AuditLogEntry entry) {
    const encoder = JsonEncoder.withIndent('  ');
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.surfaceDark,
        title: const Text('Audit entry (raw JSON)',
            style: TextStyle(fontSize: 15, color: AppTheme.textPrimary)),
        content: SizedBox(
          width: 560,
          child: SingleChildScrollView(
            child: SelectableText(
              encoder.convert(entry.toJson()),
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 11,
                color: AppTheme.textPrimary,
              ),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Future<void> _exportLog() async {
    try {
      final file = _auditLogService.paths.auditLogFile;
      if (!await file.exists()) {
        _snack('No audit log file found on disk.');
        return;
      }
      final bytes = await file.readAsBytes();
      await Printing.sharePdf(
        bytes: bytes,
        filename:
            'zero_trace_audit_log_${DateTime.now().millisecondsSinceEpoch}.jsonl',
      );
    } catch (e) {
      _snack('Export failed: $e');
    }
  }

  void _snack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  Widget _field(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 96,
            child: Text(
              label,
              style: const TextStyle(
                fontSize: 11,
                color: AppTheme.textMuted,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontSize: 11, color: AppTheme.textPrimary),
            ),
          ),
        ],
      ),
    );
  }

  Widget _chip(String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color, width: 0.8),
      ),
      child: Text(
        text,
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.bold,
          color: color,
        ),
      ),
    );
  }

  static String _formatTimestamp(String timestamp) {
    if (timestamp.length >= 19) {
      return timestamp.substring(0, 19).replaceAll('T', ' ');
    }
    return timestamp;
  }
}

class _OutcomeBadge {
  const _OutcomeBadge(this.label, this.icon, this.color);

  final String label;
  final IconData icon;
  final Color color;

  static _OutcomeBadge of(String? outcome) {
    switch (outcome) {
      case 'completed':
        return const _OutcomeBadge(
            'COMPLETED', Icons.check_circle_outline, AppTheme.simpleSuccess);
      case 'verify_failed':
        return const _OutcomeBadge(
            'VERIFICATION FAILED', Icons.warning_amber_rounded, AppTheme.accentGold);
      case 'wipe_failed':
        return const _OutcomeBadge(
            'WIPE FAILED', Icons.highlight_off, AppTheme.simpleDestructive);
      case 'interrupted':
        return const _OutcomeBadge(
            'INTERRUPTED', Icons.warning_amber_rounded, AppTheme.accentGold);
      case 'cancelled':
        return const _OutcomeBadge(
            'CANCELLED', Icons.cancel_outlined, AppTheme.accentGold);
      default:
        return const _OutcomeBadge('—', Icons.remove, AppTheme.textMuted);
    }
  }
}

class _CommandLog extends StatefulWidget {
  const _CommandLog({required this.entry});

  final AuditLogEntry entry;

  @override
  State<_CommandLog> createState() => _CommandLogState();
}

class _CommandLogState extends State<_CommandLog> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final log = widget.entry.commandLog;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          onTap: () => setState(() => _expanded = !_expanded),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                _expanded ? Icons.expand_less : Icons.expand_more,
                size: 16,
                color: AppTheme.simplePrimary,
              ),
              const SizedBox(width: 4),
              Text(
                _expanded
                    ? 'Hide command log'
                    : 'View command log (${log.length} lines)',
                style: const TextStyle(
                  fontSize: 11,
                  color: AppTheme.simplePrimary,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
        if (_expanded) ...[
          const SizedBox(height: 6),
          Container(
            width: double.infinity,
            constraints: const BoxConstraints(maxHeight: 180),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppTheme.codeBackground,
              borderRadius: BorderRadius.circular(6),
            ),
            child: SingleChildScrollView(
              child: SelectableText(
                log.take(50).map((l) => UntrustedText(l).sanitized).join('\n') +
                    (log.length > 50
                        ? '\n... [capped: ${log.length - 50} additional lines]'
                        : ''),
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 10,
                  color: Colors.white70,
                ),
              ),
            ),
          ),
        ],
      ],
    );
  }
}
