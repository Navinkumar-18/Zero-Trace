import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:printing/printing.dart';

import '../models/certificate.dart';
import '../models/untrusted_text.dart';
import '../services/audit_log_service.dart';
import '../services/certificate_service.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';
import 'certificate_dialog.dart';
import 'simple_shell.dart';

class HistoryScreen extends StatefulWidget {
  final AuditLogService? auditLogService;
  final CertificateService? certificateService;

  const HistoryScreen({
    super.key,
    this.auditLogService,
    this.certificateService,
  });

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  late final AuditLogService _auditLogService =
      widget.auditLogService ?? AuditLogService();
  late final CertificateService _certificateService =
      widget.certificateService ?? CertificateService();

  bool _isLoading = true;
  bool _showSimulated = false;
  List<AuditLogEntry> _entries = [];
  ChainIntegrityResult? _chainResult;
  bool _isVerifyingChain = true;
  final Set<String> _expandedLogs = {};

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() {
      _isLoading = true;
      _isVerifyingChain = true;
    });

    final entries = await _auditLogService.getEntries(
      limit: 100,
      includeSimulated: _showSimulated,
    );

    if (mounted) {
      setState(() {
        _entries = entries;
        _isLoading = false;
      });
    }

    // Run chain verification in background
    final chainResult = await _auditLogService.verifyChainIntegrity();
    if (mounted) {
      setState(() {
        _chainResult = chainResult;
        _isVerifyingChain = false;
      });
    }
  }

  Future<void> _exportLog() async {
    try {
      final home = Platform.environment['HOME'] ??
          Platform.environment['USERPROFILE'] ??
          '/root';
      final file = File('$home/.zero_trace/audit_log.jsonl');
      if (await file.exists()) {
        final bytes = await file.readAsBytes();
        await Printing.sharePdf(
          bytes: bytes,
          filename: 'zero_trace_audit_log_${DateTime.now().millisecondsSinceEpoch}.jsonl',
        );
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('No audit log file found on disk.')),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Export failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Column(
          children: [
            // Header Bar
            _buildHeader(),

            // Integrity Check Status Row
            _buildIntegrityRow(),

            // Simulated Filter & Count Bar
            _buildFilterBar(),

            // Content
            Expanded(
              child: _isLoading
                  ? const Center(child: CircularProgressIndicator())
                  : _entries.isEmpty
                      ? _buildEmptyState()
                      : _buildEntryList(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(
          bottom: BorderSide(color: AppTheme.surfaceBorder),
        ),
      ),
      child: Row(
        children: [
          IconButton(
            icon: const Icon(Icons.arrow_back, color: AppTheme.textPrimary),
            tooltip: 'Back',
            onPressed: () => Navigator.of(context).maybePop(),
          ),
          const SizedBox(width: 8),
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
                Text(
                  'Audit log entries with cryptographic hash-chain integrity verification',
                  style: TextStyle(
                    fontSize: 12,
                    color: AppTheme.textMuted,
                  ),
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
    Color bgColor;
    Color borderColor;
    Color iconColor;
    IconData icon;
    String title;
    String subtitle;

    if (_isVerifyingChain) {
      bgColor = AppTheme.surfaceCard;
      borderColor = AppTheme.surfaceBorder;
      iconColor = AppTheme.textMuted;
      icon = Icons.hourglass_top;
      title = 'Verifying Log Integrity...';
      subtitle = 'Computing SHA-256 hash chain verification in background';
    } else if (_chainResult == null) {
      return const SizedBox.shrink();
    } else {
      switch (_chainResult!.status) {
        case ChainIntegrityStatus.valid:
          bgColor = AppTheme.simpleSuccess.withValues(alpha: 0.1);
          borderColor = AppTheme.simpleSuccess.withValues(alpha: 0.4);
          iconColor = AppTheme.simpleSuccess;
          icon = Icons.verified_user;
          title = 'Integrity Check: Valid';
          subtitle =
              '${_chainResult!.totalEntries} chained entries verified against SHA-256 hash chain genesis.';
          break;
        case ChainIntegrityStatus.validWithLegacy:
          bgColor = AppTheme.accentGold.withValues(alpha: 0.1);
          borderColor = AppTheme.accentGold.withValues(alpha: 0.4);
          iconColor = AppTheme.accentGold;
          icon = Icons.verified_user;
          title = 'Integrity Check: Valid (with legacy entries)';
          subtitle =
              '${_chainResult!.totalEntries - _chainResult!.legacyCount} chained entries verified (${_chainResult!.legacyCount} unchained legacy entries tolerated).';
          break;
        case ChainIntegrityStatus.broken:
          bgColor = AppTheme.simpleDestructive.withValues(alpha: 0.12);
          borderColor = AppTheme.simpleDestructive.withValues(alpha: 0.5);
          iconColor = AppTheme.simpleDestructive;
          icon = Icons.gpp_maybe;
          title = 'Integrity Check: Failed at line ${_chainResult!.brokenLineNumber}';
          subtitle = _chainResult!.failureReason ?? 'Hash chain mismatch detected';
          break;
      }
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      decoration: BoxDecoration(
        color: bgColor,
        border: Border(
          bottom: BorderSide(color: borderColor),
        ),
      ),
      child: Row(
        children: [
          Icon(icon, color: iconColor, size: 24),
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
                    color: iconColor,
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
          if (!_isVerifyingChain)
            TextButton.icon(
              icon: const Icon(Icons.refresh, size: 14),
              label: const Text('Re-verify', style: TextStyle(fontSize: 11)),
              onPressed: () async {
                setState(() => _isVerifyingChain = true);
                final res = await _auditLogService.verifyChainIntegrity();
                if (mounted) {
                  setState(() {
                    _chainResult = res;
                    _isVerifyingChain = false;
                  });
                }
              },
            ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(
          bottom: BorderSide(color: AppTheme.surfaceBorder),
        ),
      ),
      child: Row(
        children: [
          Text(
            'Showing ${_entries.length} recent entries (latest 100 max)',
            style: const TextStyle(fontSize: 12, color: AppTheme.textMuted),
          ),
          const Spacer(),
          Row(
            children: [
              const Text(
                'Show simulated runs',
                style: TextStyle(fontSize: 12, color: AppTheme.textPrimary),
              ),
              const SizedBox(width: 8),
              Switch(
                value: _showSimulated,
                activeThumbColor: AppTheme.accentGold,
                onChanged: (val) {
                  setState(() => _showSimulated = val);
                  _loadData();
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.history, size: 48, color: AppTheme.textMuted),
            const SizedBox(height: 16),
            const Text(
              'No Sanitization History',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: AppTheme.textPrimary,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              _showSimulated
                  ? 'No audit log entries recorded yet.'
                  : 'No real sanitization records found. Enable "Show simulated runs" to view dry-run tests.',
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 12, color: AppTheme.textMuted),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEntryList() {
    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemCount: _entries.length,
      separatorBuilder: (_, __) => const SizedBox(height: 12),
      itemBuilder: (context, index) {
        final entry = _entries[index];
        return _buildEntryCard(entry);
      },
    );
  }

  Widget _buildEntryCard(AuditLogEntry entry) {
    final isInterrupted = entry.nistCategory == 'INTERRUPTED' ||
        entry.fingerprintHash == 'INTERRUPTED_ACKNOWLEDGED';
    final isSuccess = entry.success && !isInterrupted;

    Color statusColor;
    IconData statusIcon;
    String statusText;

    if (isInterrupted) {
      statusColor = AppTheme.accentGold;
      statusIcon = Icons.warning_amber_rounded;
      statusText = 'INTERRUPTED';
    } else if (isSuccess) {
      statusColor = AppTheme.simpleSuccess;
      statusIcon = Icons.check_circle_outline;
      statusText = 'COMPLETED';
    } else {
      statusColor = AppTheme.simpleDestructive;
      statusIcon = Icons.highlight_off;
      statusText = 'FAILED';
    }

    final isExpanded = _expandedLogs.contains(entry.jobId);
    final sanitizedDeviceName =
        UntrustedText(entry.deviceName ?? 'Unknown Device').sanitized;

    return Container(
      decoration: BoxDecoration(
        color: AppTheme.surfaceDark,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.surfaceBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Card Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            decoration: const BoxDecoration(
              border: Border(
                bottom: BorderSide(color: AppTheme.surfaceBorder),
              ),
            ),
            child: Row(
              children: [
                Icon(statusIcon, color: statusColor, size: 20),
                const SizedBox(width: 8),
                Text(
                  statusText,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: statusColor,
                  ),
                ),
                if (entry.isSimulated) ...[
                  const SizedBox(width: 8),
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: AppTheme.accentGold.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: AppTheme.accentGold, width: 0.8),
                    ),
                    child: const Text(
                      'SIMULATED',
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: AppTheme.accentGold,
                      ),
                    ),
                  ),
                ],
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    sanitizedDeviceName,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: AppTheme.textPrimary,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Text(
                  entry.timestamp.length >= 19
                      ? entry.timestamp.substring(0, 19).replaceAll('T', ' ')
                      : entry.timestamp,
                  style: const TextStyle(fontSize: 11, color: AppTheme.textMuted),
                ),
              ],
            ),
          ),

          // Card Body: Details Grid
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
                          _field('Scope', entry.scope == 'partial' ? 'Partition Wipe' : 'Full Disk'),
                          _field('Serial', entry.deviceSerial),
                          _field('Target Path', entry.devicePath),
                          _field('Standard', entry.standardReference),
                        ],
                      ),
                    ),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _field('Method', entry.method),
                          _field('Method Class', entry.methodClass ?? '—'),
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

                // Per-partition outcomes
                if (entry.partitions != null && entry.partitions!.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  const Text(
                    'Target Partitions:',
                    style: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                      color: AppTheme.textPrimary,
                    ),
                  ),
                  const SizedBox(height: 4),
                  ...entry.partitions!.map((p) => Padding(
                        padding: const EdgeInsets.only(left: 6, bottom: 2),
                        child: Text(
                          '• Partition #${p.partitionNumber}: sectors ${p.startSector}–${p.startSector + p.sizeSectors} | status: ${p.status} | wiped: ${(p.bytesWiped / (1024 * 1024)).toStringAsFixed(1)} MB',
                          style: const TextStyle(fontSize: 11, color: AppTheme.textMuted),
                        ),
                      )),
                ],

                // Command Log Section (Capped)
                if (entry.commandLog.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  InkWell(
                    onTap: () {
                      setState(() {
                        if (isExpanded) {
                          _expandedLogs.remove(entry.jobId);
                        } else {
                          _expandedLogs.add(entry.jobId);
                        }
                      });
                    },
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          isExpanded ? Icons.expand_less : Icons.expand_more,
                          size: 16,
                          color: AppTheme.simplePrimary,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          isExpanded
                              ? 'Hide Command Log'
                              : 'View Command Log (${entry.commandLog.length} lines)',
                          style: const TextStyle(
                            fontSize: 11,
                            color: AppTheme.simplePrimary,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (isExpanded) ...[
                    const SizedBox(height: 6),
                    Container(
                      width: double.infinity,
                      constraints: const BoxConstraints(maxHeight: 180),
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: AppTheme.codeBackground,
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: AppTheme.surfaceBorder),
                      ),
                      child: SingleChildScrollView(
                        child: SelectableText(
                          entry.commandLog
                              .take(50)
                              .map((line) => UntrustedText(line).sanitized)
                              .join('\n') +
                              (entry.commandLog.length > 50
                                  ? '\n... [Capped: ${entry.commandLog.length - 50} additional lines truncated]'
                                  : ''),
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 10,
                            color: AppTheme.textMuted,
                          ),
                        ),
                      ),
                    ),
                  ],
                ],
              ],
            ),
          ),

          // Card Actions (Certificate / Report)
          if (entry.certificateId != null) ...[
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: const BoxDecoration(
                border: Border(
                  top: BorderSide(color: AppTheme.surfaceBorder),
                ),
              ),
              child: Row(
                children: [
                  OutlinedButton.icon(
                    icon: Icon(
                      isSuccess ? Icons.description : Icons.report_problem,
                      size: 14,
                    ),
                    label: Text(
                      isSuccess ? 'View Certificate' : 'View Failure Report',
                      style: const TextStyle(fontSize: 11),
                    ),
                    onPressed: () async {
                      final cert = await _auditLogService
                          .getCertificateById(entry.certificateId!);
                      if (context.mounted) {
                        if (cert != null) {
                          SimpleCertificateDialog.show(context, certificate: cert);
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Certificate file not found on disk.'),
                            ),
                          );
                        }
                      }
                    },
                  ),
                  const SizedBox(width: 8),
                  OutlinedButton.icon(
                    icon: const Icon(Icons.picture_as_pdf, size: 14),
                    label: const Text('Export PDF', style: TextStyle(fontSize: 11)),
                    onPressed: () async {
                      final cert = await _auditLogService
                          .getCertificateById(entry.certificateId!);
                      if (context.mounted) {
                        if (cert != null) {
                          final pdfBytes =
                              await _certificateService.generatePdfBytes(cert);
                          await Printing.sharePdf(
                            bytes: pdfBytes,
                            filename: '${cert.certificateId}.pdf',
                          );
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Certificate file not found on disk.'),
                            ),
                          );
                        }
                      }
                    },
                  ),
                  const Spacer(),
                  if (entry.certificateSha256 != null)
                    Text(
                      'SHA: ${entry.certificateSha256!.substring(0, 10)}...',
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 10,
                        color: AppTheme.textMuted,
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

  Widget _field(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 90,
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
              style: const TextStyle(
                fontSize: 11,
                color: AppTheme.textPrimary,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
