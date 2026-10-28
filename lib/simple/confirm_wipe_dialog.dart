import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/partition_info.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';
import '../services/classification_service.dart';
import '../services/filesystem_recreation_preference.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

/// Capability-style token proving the user confirmed device identity
/// and authorized the wipe inside [SimpleConfirmDialog].
class WipeAuthorization {
  final DateTime authorizedAt;
  final String deviceSerial;
  final DisposalIntent intent;
  final SanitizationMethod? overrideMethod;

  /// The exact text the operator typed into the confirmation field. The token is
  /// only ever constructed after that text matched the pinned device identity,
  /// so this records which typed confirmation produced the authorization.
  final String typedConfirmation;

  /// Phase G: the single pre-wipe "After wiping" decision.
  ///
  /// `true`  → recreate an empty filesystem automatically after a verified
  ///           wipe (the captured [restoreFsType]/[restoreLabel] are used).
  /// `false` → leave the drive blank; the UI then offers "Restore now".
  final bool restoreFilesystem;

  /// Filesystem captured from the original volume before the wipe (normalized
  /// to one the engine supports), or the remembered preference, or `vfat`.
  final String? restoreFsType;

  /// Original volume label captured before the wipe, or the remembered
  /// preference. The engine sanitizes it again before formatting.
  final String? restoreLabel;

  WipeAuthorization._({
    required this.authorizedAt,
    required this.deviceSerial,
    required this.intent,
    required this.typedConfirmation,
    this.overrideMethod,
    this.restoreFilesystem = false,
    this.restoreFsType,
    this.restoreLabel,
  });

  /// Factory for testing fixtures only.
  @visibleForTesting
  factory WipeAuthorization.forTesting({
    required String deviceSerial,
    DisposalIntent intent = DisposalIntent.reuseMyself,
    SanitizationMethod? overrideMethod,
    String typedConfirmation = '',
    bool restoreFilesystem = false,
    String? restoreFsType,
    String? restoreLabel,
  }) {
    return WipeAuthorization._(
      authorizedAt: DateTime.now(),
      deviceSerial: deviceSerial,
      intent: intent,
      typedConfirmation: typedConfirmation,
      overrideMethod: overrideMethod,
      restoreFilesystem: restoreFilesystem,
      restoreFsType: restoreFsType,
      restoreLabel: restoreLabel,
    );
  }
}

/// Result from the confirm dialog: intent, optional method override, and authorization token.
class ConfirmWipeResult {
  final DisposalIntent intent;
  final SanitizationMethod? overrideMethod;
  final WipeAuthorization authorization;

  const ConfirmWipeResult({
    required this.intent,
    required this.authorization,
    this.overrideMethod,
  });
}

class SimpleConfirmDialog extends StatefulWidget {
  final DeviceProfile device;

  const SimpleConfirmDialog({super.key, required this.device});

  /// Show the dialog and return the result, or null if cancelled.
  static Future<ConfirmWipeResult?> show(BuildContext context, DeviceProfile device) {
    return showDialog<ConfirmWipeResult>(
      context: context,
      barrierDismissible: false,
      builder: (_) => ChangeNotifierProvider.value(
        value: context.read<SanitizationController>(),
        child: SimpleConfirmDialog(device: device),
      ),
    );
  }

  @override
  State<SimpleConfirmDialog> createState() => _SimpleConfirmDialogState();
}

class _SimpleConfirmDialogState extends State<SimpleConfirmDialog> {
  DisposalIntent _intent = DisposalIntent.reuseMyself;
  final TextEditingController _serialController = TextEditingController();
  bool _isMatch = false;

  /// Phase G: one pre-wipe decision about the drive's post-wipe state.
  /// Defaults to restoring removable media (the common "make it usable
  /// again" case) and to leaving internal/system-adjacent media blank.
  late bool _restoreFilesystem;

  /// Normalization applied to both the typed input and the expected token:
  /// case-insensitive, whitespace-insensitive.
  String _normalize(String value) =>
      value.trim().toLowerCase().replaceAll(RegExp(r'\s+'), '');

  /// Last 4 characters of the serial, or '' when the device has no usable
  /// serial (empty or the generic 'S/N-…' placeholder from enumeration).
  String get _serialToken {
    final serial = widget.device.serialNumber.trim();
    if (serial.isNotEmpty && !serial.startsWith('S/N-')) {
      return serial.length >= 4 ? serial.substring(serial.length - 4) : serial;
    }
    return '';
  }

  bool get _useFallbackMatch => _serialToken.isEmpty;

  /// A5: partitions selected for a partition-scope wipe (empty = whole device).
  List<PartitionInfo> get _scopePartitions =>
      context.read<SanitizationController>().selectedPartitions;

  /// A5: internal disks require the serial last-4 PLUS the partition name(s)
  /// so the operator cannot authorize a partition wipe by rote muscle memory.
  bool get _requiresPartitionToken =>
      !widget.device.isRemovable && _scopePartitions.isNotEmpty;

  /// A5: serial-less fallback token = device model + size (documented in the
  /// prompt so the operator knows exactly what to type).
  String get _fallbackToken =>
      _normalize('${widget.device.name} ${widget.device.capacityBytes}');

  /// The exact token the operator must type to enable the wipe button.
  String get _expectedTypedConfirmation {
    if (_useFallbackMatch) return _fallbackToken;
    if (_requiresPartitionToken) {
      final names = _scopePartitions.map((p) => p.name).join(' ');
      return _normalize('$_serialToken $names');
    }
    return _normalize(_serialToken);
  }

  bool _checkAmbiguousFallback(SanitizationController controller) {
    if (!_useFallbackMatch) return false;
    final targetKey = _fallbackToken;
    final matchingDrives = controller.devices.where((d) {
      final key = _normalize('${d.name} ${d.capacityBytes}');
      return key == targetKey;
    }).toList();
    return matchingDrives.length > 1;
  }

  void _onTextChanged() {
    final controller = context.read<SanitizationController>();
    if (_checkAmbiguousFallback(controller)) {
      setState(() => _isMatch = false);
      return;
    }
    setState(() =>
        _isMatch = _normalize(_serialController.text) == _expectedTypedConfirmation);
  }

  @override
  void initState() {
    super.initState();
    _restoreFilesystem = widget.device.isRemovable;
    _serialController.addListener(_onTextChanged);
  }

  @override
  void dispose() {
    _serialController.removeListener(_onTextChanged);
    _serialController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final isSimulated = !controller.isRealMode;
    final hasAmbiguousFallback = _checkAmbiguousFallback(controller);
    // A5: what exactly gets wiped — selected partitions, or the whole device.
    final selectedParts = controller.selectedPartitions;
    final rec = controller.getAutoMethod(widget.device, _intent);
    final method = rec.method;
    final supportLevel = computeSupportLevel(widget.device);
    final isDestroyRecommended =
        method == SanitizationMethod.physicalDestructionRecommended ||
        method == SanitizationMethod.unsupportedFlagForDestroy;
    final isFlash = widget.device.mediaTechnology == MediaTechnology.flash;
    final isUnknown = widget.device.mediaTechnology == MediaTechnology.unknown;
    final isClearOnly = supportLevel == SanitizationSupportLevel.clearOnly;

    // Phase G: capture the original filesystem + label now, before the wipe,
    // so the restore needs no second prompt afterwards. Partition scope uses
    // the selected partition; whole-device uses the first partition. Both
    // fall back to the remembered preference, then to vfat.
    final restoreTarget = selectedParts.isNotEmpty
        ? selectedParts.first
        : (widget.device.partitions.isNotEmpty
              ? widget.device.partitions.first
              : null);
    final restoreFsType =
        normalizeFilesystemType(restoreTarget?.fsType) ??
        controller.formatPreference.fsType ??
        'vfat';
    final restoreLabel = _captureRestoreLabel(
      restoreTarget,
      controller.formatPreference,
      wholeDevice: selectedParts.isEmpty,
    );

    return Dialog(
      backgroundColor: AppTheme.surfaceDark,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: const BorderSide(color: AppTheme.accentRose, width: 1.5),
      ),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 480),
        padding: const EdgeInsets.all(24.0),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Simulation banner
              if (isSimulated) ...[
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: AppTheme.accentGold.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: AppTheme.accentGold.withValues(alpha: 0.5),
                    ),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.science, color: AppTheme.accentGold, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'SIMULATION MODE — Virtual Wipe',
                          style: TextStyle(
                            color: AppTheme.accentGold,
                            fontWeight: FontWeight.bold,
                            fontSize: 11,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 14),
              ],

              // Warning header
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: AppTheme.accentRose.withValues(alpha: 0.15),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.warning_amber_rounded,
                        color: AppTheme.accentRose, size: 28),
                  ),
                  const SizedBox(width: 14),
                  const Expanded(
                    child: Text('Wipe All Data?',
                        style: TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                            color: AppTheme.textPrimary)),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              const Divider(color: AppTheme.surfaceBorder),
              const SizedBox(height: 12),

              // Ambiguous match warning
              if (hasAmbiguousFallback) ...[
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppTheme.accentRose.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.accentRose.withValues(alpha: 0.5)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.block, color: AppTheme.accentRose, size: 20),
                      SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'Ambiguous device match: Multiple drives match this fallback signature. Wiping is blocked for safety.',
                          style: TextStyle(
                            color: AppTheme.accentRose,
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
              ],

              _infoRow('Drive:', widget.device.name),
              const SizedBox(height: 4),
              _infoRow('Size:', widget.device.formattedCapacity),
              const SizedBox(height: 4),
              _infoRow('Serial:', widget.device.serialNumber),
              const SizedBox(height: 4),
              _infoRow('Method:', _methodDisplayText(method, isDestroyRecommended)),
              const SizedBox(height: 4),
              // A5: exact scope (partitions + sizes) and the level it yields.
              // B4: entire-disk wording states the partition table dies too.
              _infoRow(
                'Scope:',
                selectedParts.isEmpty
                    ? 'Entire device (all partitions + partition table, '
                        '${widget.device.formattedCapacity})'
                    : selectedParts
                        .map((p) => '${p.name} (${p.formattedSize})')
                        .join(', '),
              ),
              // B2: encrypted volumes (BitLocker / LUKS) remain wipeable —
              // the operator must know before confirming.
              if (_encryptionKindsInScope(selectedParts).isNotEmpty) ...[
                const SizedBox(height: 4),
                _infoRow(
                  'Encryption:',
                  '${_encryptionKindsInScope(selectedParts).join(', ')} '
                      'detected — wiping works regardless of encryption.',
                ),
              ],
              const SizedBox(height: 4),
              _infoRow('Level:', _levelText(supportLevel, selectedParts.isEmpty)),
              const SizedBox(height: 4),
              _infoRow('Est. Duration:', _estimateDisplayText(widget.device, method)),
              if (widget.device.driveType == DriveType.usb ||
                  widget.device.mediaType == MediaType.usbFlash ||
                  widget.device.busType.toUpperCase() == 'USB') ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppTheme.accentBlue.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppTheme.accentBlue.withValues(alpha: 0.3)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.usb, color: AppTheme.accentBlue, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Connecting to a USB 3 port is strongly recommended for faster write speeds.',
                          style: TextStyle(color: AppTheme.accentBlue, fontSize: 11),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
              if (isClearOnly && isFlash) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppTheme.accentGold.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.info_outline, color: AppTheme.accentGold, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Flash media: overwrite cannot reach remapped blocks. '
                          'Result will be "Clear" level, not "Purge".',
                          style: TextStyle(color: AppTheme.accentGold, fontSize: 11),
                        ),
                      ),
                    ],
                  ),
                ),
              ] else if (isClearOnly && isUnknown) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: AppTheme.accentGold.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.info_outline, color: AppTheme.accentGold, size: 16),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Clear level only. Logical overwrite cannot guarantee firmware-level purge.',
                          style: TextStyle(color: AppTheme.accentGold, fontSize: 11),
                        ),
                      ),
                    ],
                  ),
                ),
              ],

              const SizedBox(height: 16),

              // Disposal question
              const Text('What will happen to this drive?',
                  style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: AppTheme.textPrimary)),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
                decoration: BoxDecoration(
                  color: AppTheme.surfaceCard,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: AppTheme.surfaceBorder),
                ),
                child: DropdownButton<DisposalIntent>(
                  value: _intent,
                  isExpanded: true,
                  underline: const SizedBox.shrink(),
                  items: DisposalIntent.values.map((e) => DropdownMenuItem(
                    value: e,
                    child: Text(e.label),
                  )).toList(),
                  onChanged: (val) {
                    if (val != null) setState(() => _intent = val);
                  },
                ),
              ),

              // Destroy recommendation
              if (isDestroyRecommended) ...[
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppTheme.accentRose.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.accentRose.withValues(alpha: 0.4)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Row(
                        children: [
                          Icon(Icons.gpp_bad, color: AppTheme.accentRose, size: 18),
                          SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              'Physical destruction recommended',
                              style: TextStyle(
                                  color: AppTheme.accentRose,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 12),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'This device cannot be reliably purged. Overwrite will '
                        'achieve Clear only. Residual data may remain.',
                        style: TextStyle(color: AppTheme.textSecondary, fontSize: 11),
                      ),
                      const SizedBox(height: 8),
                      TextButton(
                        onPressed: () {
                          // The override method will be singlePassOverwrite (Clear only)
                          if (!_isMatch || hasAmbiguousFallback) return;
                          final auth = WipeAuthorization._(
                            authorizedAt: DateTime.now(),
                            deviceSerial: widget.device.serialNumber,
                            intent: _intent,
                            typedConfirmation: _serialController.text,
                            overrideMethod: SanitizationMethod.singlePassOverwrite,
                            restoreFilesystem: _restoreFilesystem,
                            restoreFsType: restoreFsType,
                            restoreLabel: restoreLabel,
                          );
                          Navigator.of(context).pop(ConfirmWipeResult(
                            intent: _intent,
                            overrideMethod: SanitizationMethod.singlePassOverwrite,
                            authorization: auth,
                          ));
                        },
                        child: Text(
                          'Wipe anyway (Clear only)',
                          style: TextStyle(
                            color: (_isMatch && !hasAmbiguousFallback) ? AppTheme.accentGold : AppTheme.textMuted,
                            fontWeight: FontWeight.w600,
                            fontSize: 12,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],

              const SizedBox(height: 16),

              // Phase G: ONE question about the drive's post-wipe state,
              // asked before the wipe so the restore can happen automatically.
              const Text('After wiping:',
                  style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: AppTheme.textPrimary)),
              const SizedBox(height: 4),
              RadioGroup<bool>(
                groupValue: _restoreFilesystem,
                onChanged: (value) {
                  if (value != null) {
                    setState(() => _restoreFilesystem = value);
                  }
                },
                child: Column(
                  children: [
                    RadioListTile<bool>(
                      key: const Key('after-wipe-restore'),
                      value: true,
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      activeColor: AppTheme.simplePrimary,
                      title: const Text(
                        'Restore as an empty drive',
                        style: TextStyle(
                          fontSize: 13,
                          color: AppTheme.textPrimary,
                        ),
                      ),
                      subtitle: Text(
                        'Recreates a ${restoreFsType.toUpperCase()} filesystem'
                        '${restoreLabel.isNotEmpty ? ' labelled $restoreLabel' : ''} '
                        'after the wipe is verified.',
                        style: const TextStyle(
                          fontSize: 11,
                          color: AppTheme.textMuted,
                        ),
                      ),
                    ),
                    RadioListTile<bool>(
                      key: const Key('after-wipe-leave-blank'),
                      value: false,
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      activeColor: AppTheme.simplePrimary,
                      title: const Text(
                        "Leave blank (won't appear in file manager until formatted)",
                        style: TextStyle(
                          fontSize: 13,
                          color: AppTheme.textPrimary,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 16),

              // Serial confirmation
              Text(
                _useFallbackMatch
                    ? 'Type device model and size to confirm '
                        '(${widget.device.name} ${widget.device.capacityBytes}):'
                    : _requiresPartitionToken
                        ? 'Type the last 4 characters of the serial followed by '
                            'the partition name(s) to confirm:'
                        : 'Type the last 4 characters of the serial to confirm:',
                style: const TextStyle(fontSize: 12, color: AppTheme.textSecondary),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _serialController,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 15,
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                ),
                decoration: InputDecoration(
                  hintText: _useFallbackMatch
                      ? '${widget.device.name}${widget.device.capacityBytes}'
                      : _requiresPartitionToken
                          ? '$_serialToken ${_scopePartitions.map((p) => p.name).join(' ')}'
                          : '****',
                  hintStyle: TextStyle(
                    color: AppTheme.textMuted.withValues(alpha: 0.5),
                    fontWeight: FontWeight.normal,
                  ),
                  filled: true,
                  fillColor: Colors.white,
                  contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: AppTheme.surfaceBorder),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: BorderSide(
                      color: _isMatch ? AppTheme.accentEmerald : AppTheme.accentRose,
                      width: 2.0,
                    ),
                  ),
                ),
              ),

              const SizedBox(height: 20),

              // Actions
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(null),
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: AppTheme.surfaceBorder),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                      child: const Text('Cancel'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      icon: const Icon(Icons.delete_forever, size: 20),
                      label: const Text('SECURE WIPE',
                          style: TextStyle(fontWeight: FontWeight.bold)),
                      onPressed: (!_isMatch || isDestroyRecommended || hasAmbiguousFallback)
                          ? null
                          : () {
                              // Re-check pinned identity in controller.devices
                              final current = controller.devices.cast<DeviceProfile?>().firstWhere(
                                (d) => d!.stableId == widget.device.stableId,
                                orElse: () => null,
                              );
                              if (current == null ||
                                  current.serialNumber != widget.device.serialNumber ||
                                  current.capacityBytes != widget.device.capacityBytes) {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(
                                    content: Text('Drive identity changed or disconnected.'),
                                    backgroundColor: AppTheme.accentRose,
                                  ),
                                );
                                Navigator.of(context).pop(null);
                                return;
                              }
                              final auth = WipeAuthorization._(
                                authorizedAt: DateTime.now(),
                                deviceSerial: widget.device.serialNumber,
                                intent: _intent,
                                typedConfirmation: _serialController.text,
                                restoreFilesystem: _restoreFilesystem,
                                restoreFsType: restoreFsType,
                                restoreLabel: restoreLabel,
                              );
                              Navigator.of(context).pop(ConfirmWipeResult(
                                intent: _intent,
                                authorization: auth,
                              ));
                            },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.simpleDestructive,
                        foregroundColor: Colors.white,
                        disabledBackgroundColor: AppTheme.surfaceBorder,
                        disabledForegroundColor: AppTheme.textMuted,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// Phase G: the volume label to hand to the automatic restore. The
  /// partition's own label wins, then the remembered preference, then a
  /// stable default (device name for whole-device, `ZT_VOLUME` otherwise).
  String _captureRestoreLabel(
    PartitionInfo? target,
    FilesystemRecreationPreference preference, {
    required bool wholeDevice,
  }) {
    final partLabel = target?.label.sanitized.trim() ?? '';
    if (partLabel.isNotEmpty) return partLabel;
    final remembered = preference.label?.trim() ?? '';
    if (remembered.isNotEmpty) return remembered;
    return wholeDevice ? widget.device.name : 'ZT_VOLUME';
  }

  String _methodDisplayText(SanitizationMethod method, bool isDestroy) {
    if (isDestroy) return 'Physical destruction recommended';
    return '${method.displayName} (auto)';
  }

  /// A5: NIST SP 800-88 level this wipe will actually achieve.
  /// Partition scope, unsupported media and clear-only media cap at Clear;
  /// whole-device wipes on hardware-command-capable devices reach Purge.
  /// B2: distinct encryption kinds (BitLocker / LUKS) present in the wipe
  /// scope. Whole-device scope scans every partition of the drive.
  List<String> _encryptionKindsInScope(List<PartitionInfo> selectedParts) {
    final scope =
        selectedParts.isNotEmpty ? selectedParts : widget.device.partitions;
    return [
      ...{
        for (final p in scope)
          if (p.encryptionKind != null) p.encryptionKind!,
      }
    ];
  }

  String _levelText(SanitizationSupportLevel supportLevel, bool wholeDevice) {
    if (supportLevel == SanitizationSupportLevel.unsupported) {
      return 'Clear at best — purge not supported by this device';
    }
    if (supportLevel == SanitizationSupportLevel.clearOnly) {
      return 'Clear — purge not achievable on this media';
    }
    final level = ClassificationService()
        .capabilityMatrix(widget.device)
        .sanitizationLevel(wholeDevice: wholeDevice);
    if (level == 'Purge') return 'Purge (NIST SP 800-88 Rev. 1)';
    return wholeDevice
        ? 'Clear (NIST SP 800-88 Rev. 1) — no hardware purge command available'
        : 'Clear (NIST SP 800-88 Rev. 1) — partition scope never reaches Purge';
  }

  String _estimateDisplayText(DeviceProfile device, SanitizationMethod method) {
    if (method == SanitizationMethod.cryptographicErase ||
        method == SanitizationMethod.nvmeSanitize ||
        method == SanitizationMethod.ataSanitizeBlockErase) {
      return 'Estimate: ~1 to 5 min (firmware purge)';
    }
    if (method == SanitizationMethod.ataSecureErase) {
      if (device.mediaTechnology == MediaTechnology.rotational) {
        return 'Estimate: ~1 to 3+ hours (firmware erase)';
      }
      return 'Estimate: ~2 to 20 min (firmware erase)';
    }
    final bytes = device.capacityBytes;
    final isMultiPass = method == SanitizationMethod.multiPassOverwrite;
    if (bytes <= 32 * 1024 * 1024 * 1024) {
      return isMultiPass
          ? 'Estimate: ~45 min to 4+ hours'
          : 'Estimate: ~15 to 90 min';
    } else if (bytes <= 128 * 1024 * 1024 * 1024) {
      return isMultiPass
          ? 'Estimate: ~2 to 9+ hours'
          : 'Estimate: ~45 min to 3+ hours';
    } else if (bytes <= 512 * 1024 * 1024 * 1024) {
      return isMultiPass
          ? 'Estimate: ~6 to 24+ hours'
          : 'Estimate: ~2 to 8+ hours';
    } else {
      return isMultiPass
          ? 'Estimate: ~12 to 48+ hours'
          : 'Estimate: ~4 to 16+ hours';
    }
  }

  Widget _infoRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 80,
          child: Text(label,
              style: const TextStyle(
                  fontSize: 12,
                  color: AppTheme.textMuted,
                  fontWeight: FontWeight.w600)),
        ),
        Expanded(
          child: Text(value,
              style: const TextStyle(
                  fontSize: 12,
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.w500)),
        ),
      ],
    );
  }
}
