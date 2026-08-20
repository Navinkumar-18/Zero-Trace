import 'package:flutter/material.dart';
import '../models/device_profile.dart';
import '../models/sanitization_job.dart';
import 'theme.dart';

class ConfirmationDialog extends StatefulWidget {
  final DeviceProfile device;
  final SanitizationMethod method;
  final String nistCategory;

  const ConfirmationDialog({
    super.key,
    required this.device,
    required this.method,
    required this.nistCategory,
  });

  static Future<bool> show(
    BuildContext context, {
    required DeviceProfile device,
    required SanitizationMethod method,
    required String nistCategory,
  }) async {
    return await showDialog<bool>(
          context: context,
          barrierDismissible: false,
          builder: (context) => ConfirmationDialog(
            device: device,
            method: method,
            nistCategory: nistCategory,
          ),
        ) ??
        false;
  }

  @override
  State<ConfirmationDialog> createState() => _ConfirmationDialogState();
}

class _ConfirmationDialogState extends State<ConfirmationDialog> {
  final TextEditingController _controller = TextEditingController();
  bool _isMatch = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(_onTextChanged);
  }

  void _onTextChanged() {
    final expected = widget.device.serialNumber.trim();
    final actual = _controller.text.trim();
    setState(() {
      _isMatch = expected == actual;
    });
  }

  @override
  void dispose() {
    _controller.removeListener(_onTextChanged);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppTheme.surfaceDark,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: const BorderSide(color: AppTheme.accentRose, width: 1.5),
      ),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 480),
        padding: const EdgeInsets.all(24.0),
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
                  child: const Icon(
                    Icons.warning_amber_rounded,
                    color: AppTheme.accentRose,
                    size: 32,
                  ),
                ),
                const SizedBox(width: 14),
                const Expanded(
                  child: Text(
                    'Irreversible Sanitization',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: AppTheme.textPrimary,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),
            const Divider(color: AppTheme.surfaceBorder),
            const SizedBox(height: 14),

            // Warning note
            const Text(
              'WARNING: This action is destructive and permanent. All data, logical tables, partition tables, and firmware-level storage cells will be sanitized. Data recovery will be impossible.',
              style: TextStyle(
                color: AppTheme.accentRose,
                fontSize: 13,
                height: 1.4,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 18),

            // Target details card
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppTheme.surfaceCard,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppTheme.surfaceBorder),
              ),
              child: Column(
                children: [
                  _buildDetailRow('Target Device:', widget.device.name),
                  const SizedBox(height: 6),
                  _buildDetailRow('Device Serial:', widget.device.serialNumber, isHighlight: true),
                  const SizedBox(height: 6),
                  _buildDetailRow('Interface / Bus:', widget.device.busType),
                  const SizedBox(height: 6),
                  _buildDetailRow('Applied Method:', widget.method.displayName),
                  const SizedBox(height: 6),
                  _buildDetailRow('NIST SP 800-88:', widget.nistCategory),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Prompt instructions
            const Text(
              'To confirm this action, please type the device serial number below:',
              style: TextStyle(
                fontSize: 13,
                color: AppTheme.textSecondary,
              ),
            ),
            const SizedBox(height: 10),

            // Input field
            TextField(
              controller: _controller,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 15,
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
              ),
              decoration: InputDecoration(
                hintText: 'Enter serial number',
                hintStyle: TextStyle(
                  fontFamily: 'sans-serif',
                  color: AppTheme.textMuted.withValues(alpha: 0.7),
                  fontWeight: FontWeight.normal,
                ),
                filled: true,
                fillColor: AppTheme.codeBackground,
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
            const SizedBox(height: 24),

            // Actions row
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(false),
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: AppTheme.surfaceBorder),
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: const Text('CANCEL'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: ElevatedButton(
                    onPressed: _isMatch ? () => Navigator.of(context).pop(true) : null,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.accentRose,
                      foregroundColor: Colors.white,
                      disabledBackgroundColor: AppTheme.surfaceBorder,
                      disabledForegroundColor: AppTheme.textMuted,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                    ),
                    child: const Text(
                      'CONFIRM ERASE',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, {bool isHighlight = false}) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: const TextStyle(
              fontSize: 12,
              color: AppTheme.textMuted,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: TextStyle(
              fontSize: 12,
              color: isHighlight ? AppTheme.accentGold : AppTheme.textPrimary,
              fontWeight: isHighlight ? FontWeight.bold : FontWeight.w500,
              fontFamily: isHighlight ? 'monospace' : 'sans-serif',
            ),
          ),
        ),
      ],
    );
  }
}
