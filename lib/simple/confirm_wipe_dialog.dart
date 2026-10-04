import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import '../models/sanitization_support_level.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

/// Result from the confirm dialog: intent + optional method override.
class ConfirmWipeResult {
  final DisposalIntent intent;
  final SanitizationMethod? overrideMethod;

  const ConfirmWipeResult({required this.intent, this.overrideMethod});
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

  String get _expectedToken {
    final serial = widget.device.serialNumber.trim();
    if (serial.isNotEmpty && !serial.startsWith('S/N-')) {
      return serial.length >= 4 ? serial.substring(serial.length - 4) : serial;
    }
    // Fallback: device path + size
    return '';
  }

  bool get _useFallbackMatch => _expectedToken.isEmpty;

  void _onTextChanged() {
    final input = _serialController.text.trim().toLowerCase().replaceAll(RegExp(r'\s+'), '');

    if (_useFallbackMatch) {
      // Match device path + formatted size
      final expected = '${widget.device.id}${widget.device.capacityBytes}'
          .toLowerCase()
          .replaceAll(RegExp(r'\s+'), '');
      setState(() => _isMatch = input == expected);
    } else {
      final expected = _expectedToken.toLowerCase().replaceAll(RegExp(r'\s+'), '');
      setState(() => _isMatch = input == expected);
    }
  }

  @override
  void initState() {
    super.initState();
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
    final rec = controller.getAutoMethod(widget.device, _intent);
    final method = rec.method;
    final supportLevel = computeSupportLevel(widget.device);
    final isDestroyRecommended =
        method == SanitizationMethod.physicalDestructionRecommended ||
        method == SanitizationMethod.unsupportedFlagForDestroy;
    final isFlash = widget.device.mediaType == MediaType.usbFlash ||
        widget.device.mediaType == MediaType.emmc;
    final isClearOnly = supportLevel == SanitizationSupportLevel.clearOnly;

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

              // Drive info
              _infoRow('Drive:', widget.device.name),
              const SizedBox(height: 4),
              _infoRow('Size:', widget.device.formattedCapacity),
              const SizedBox(height: 4),
              _infoRow('Serial:', widget.device.serialNumber),
              const SizedBox(height: 4),
              _infoRow('Method:', _methodDisplayText(method, isDestroyRecommended)),
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
                          if (!_isMatch) return;
                          Navigator.of(context).pop(ConfirmWipeResult(
                            intent: _intent,
                            overrideMethod: SanitizationMethod.singlePassOverwrite,
                          ));
                        },
                        child: Text(
                          'Wipe anyway (Clear only)',
                          style: TextStyle(
                            color: _isMatch ? AppTheme.accentGold : AppTheme.textMuted,
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

              // Serial confirmation
              Text(
                _useFallbackMatch
                    ? 'Type the device path and size to confirm:'
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
                  hintText: _useFallbackMatch ? 'device_id + size' : '****',
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
                      onPressed: (!_isMatch || isDestroyRecommended)
                          ? null
                          : () => Navigator.of(context).pop(
                              ConfirmWipeResult(intent: _intent)),
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

  String _methodDisplayText(SanitizationMethod method, bool isDestroy) {
    if (isDestroy) return 'Physical destruction recommended';
    return '${method.displayName} (auto)';
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
