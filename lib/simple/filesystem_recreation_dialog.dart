import 'package:flutter/material.dart';

import '../models/filesystem_recreation.dart';
import '../services/filesystem_recreation_preference.dart';
import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

/// Phase F: "Recreate filesystem?" prompt shown after a wipe was verified.
///
/// The format action is always OFF when the dialog opens, regardless of any
/// remembered preference. The wipe result is already recorded and is never
/// changed by this step.
class FilesystemRecreationDialog extends StatefulWidget {
  final SanitizationController controller;
  final FilesystemRecreationDefaults defaults;

  const FilesystemRecreationDialog({
    super.key,
    required this.controller,
    required this.defaults,
  });

  static Future<void> show(
    BuildContext context,
    SanitizationController controller,
  ) {
    final defaults = controller.filesystemRecreationDefaults;
    if (defaults == null) return Future<void>.value();
    return showDialog<void>(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => FilesystemRecreationDialog(
        controller: controller,
        defaults: defaults,
      ),
    );
  }

  @override
  State<FilesystemRecreationDialog> createState() =>
      _FilesystemRecreationDialogState();
}

class _FilesystemRecreationDialogState
    extends State<FilesystemRecreationDialog> {
  late String _fsType;
  late final TextEditingController _labelController;
  final TextEditingController _confirmationController = TextEditingController();
  bool _enabled = false;
  bool _submitting = false;
  String? _error;

  bool get _isWholeDevice => widget.defaults.scope == 'full';

  @override
  void initState() {
    super.initState();
    _fsType = widget.defaults.fsType;
    _labelController = TextEditingController(text: widget.defaults.label);
  }

  @override
  void dispose() {
    _labelController.dispose();
    _confirmationController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_enabled || _submitting) return;
    setState(() {
      _submitting = true;
      _error = null;
    });

    final record = await widget.controller.recreateFilesystem(
      fsType: _fsType,
      label: _labelController.text,
      confirmationToken: _confirmationController.text,
      tableType: widget.defaults.tableType,
    );

    if (!mounted) return;
    if (record != null) {
      Navigator.of(context).pop();
      return;
    }
    setState(() {
      _submitting = false;
      _error =
          widget.controller.filesystemRecreationError ??
          'Filesystem recreation failed.';
    });
    // Keep the wipe result untouched; the failure is shown inline.
  }

  @override
  Widget build(BuildContext context) {
    final error = _error ?? widget.controller.filesystemRecreationError;
    return AlertDialog(
      backgroundColor: AppTheme.surfaceDark,
      title: const Row(
        children: [
          Icon(Icons.storage_rounded, color: AppTheme.simplePrimary),
          SizedBox(width: 8),
          Expanded(child: Text('Recreate filesystem?')),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'The wipe has already completed and its result is recorded. '
              'Recreating a filesystem does not change the sanitization '
              'verdict — it only makes the drive usable again.',
              style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
            ),
            const SizedBox(height: 12),
            Text(
              _isWholeDevice
                  ? 'Target: whole device — a new ${widget.defaults.tableType?.toUpperCase() ?? 'GPT'} '
                        'table with ONE partition will be created. The original '
                        'partition layout is not restored.'
                  : 'Target: the wiped partition.',
              style: const TextStyle(
                color: AppTheme.textSecondary,
                fontSize: 12,
              ),
            ),
            const SizedBox(height: 8),
            CheckboxListTile(
              key: const Key('filesystem-recreate-toggle'),
              contentPadding: EdgeInsets.zero,
              value: _enabled,
              onChanged: _submitting
                  ? null
                  : (value) => setState(() => _enabled = value ?? false),
              title: const Text(
                'Recreate filesystem',
                style: TextStyle(fontSize: 13),
              ),
              subtitle: const Text(
                'Off by default. Nothing is formatted unless you enable this.',
                style: TextStyle(fontSize: 11, color: AppTheme.textMuted),
              ),
              activeColor: AppTheme.simplePrimary,
              controlAffinity: ListTileControlAffinity.leading,
            ),
            if (_enabled) ...[
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                key: const Key('filesystem-type-dropdown'),
                initialValue: _fsType,
                decoration: const InputDecoration(
                  labelText: 'Filesystem',
                  border: OutlineInputBorder(),
                ),
                items: [
                  for (final fs in supportedFilesystemTypes)
                    DropdownMenuItem(value: fs, child: Text(fs)),
                ],
                onChanged: _submitting
                    ? null
                    : (value) => setState(() => _fsType = value ?? _fsType),
              ),
              const SizedBox(height: 10),
              TextField(
                key: const Key('filesystem-label-field'),
                controller: _labelController,
                enabled: !_submitting,
                maxLength: 11,
                decoration: const InputDecoration(
                  labelText: 'Volume label',
                  border: OutlineInputBorder(),
                ),
              ),
              if (_isWholeDevice) ...[
                const SizedBox(height: 4),
                Text(
                  'Type the device serial to confirm: '
                  '${widget.controller.currentJob?.device.serialNumber ?? ''}',
                  style: const TextStyle(
                    color: AppTheme.accentGold,
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 6),
                TextField(
                  key: const Key('filesystem-confirmation-field'),
                  controller: _confirmationController,
                  enabled: !_submitting,
                  decoration: const InputDecoration(
                    labelText: 'Device serial',
                    border: OutlineInputBorder(),
                  ),
                ),
              ],
            ],
            if (error != null) ...[
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppTheme.accentRose.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: AppTheme.accentRose.withValues(alpha: 0.4),
                  ),
                ),
                child: Text(
                  'Format failed: $error',
                  key: const Key('filesystem-recreate-error'),
                  style: const TextStyle(
                    color: AppTheme.accentRose,
                    fontSize: 12,
                  ),
                ),
              ),
            ],
            if (_submitting) ...[
              const SizedBox(height: 12),
              const Row(
                children: [
                  SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  SizedBox(width: 10),
                  Text(
                    'Recreating filesystem...',
                    style: TextStyle(fontSize: 12, color: AppTheme.textMuted),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          key: const Key('filesystem-recreate-not-now'),
          onPressed: _submitting
              ? null
              : () {
                  widget.controller.dismissFilesystemRecreationPrompt();
                  Navigator.of(context).pop();
                },
          child: const Text('Not now'),
        ),
        ElevatedButton(
          key: const Key('filesystem-recreate-confirm'),
          onPressed: (_enabled && !_submitting) ? _submit : null,
          child: const Text('Recreate filesystem'),
        ),
      ],
    );
  }
}
