import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../../models/assistant_context.dart';
import '../../../models/device_profile.dart';
import '../../../services/ai_service.dart';
import '../../../services/assistant_context_builder.dart';
import '../../../services/sanitization_controller.dart';
import '../../../widgets/theme.dart';

class AiAssistantScreen extends StatefulWidget {
  const AiAssistantScreen({super.key});

  @override
  State<AiAssistantScreen> createState() => _AiAssistantScreenState();
}

class _AiAssistantScreenState extends State<AiAssistantScreen> {
  final AiService _aiService = AiService();
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final List<_ChatMessage> _messages = [];

  // Local assistant device selection (decoupled from controller.selectedDevice)
  DeviceProfile? _assistantDevice;
  bool _deviceCleared = false;

  @override
  void initState() {
    super.initState();
    // Welcome message
    _messages.add(_ChatMessage(
      isUser: false,
      text: 'Welcome to the Zero Trace AI Assistant.\n\n'
          'I can help you understand storage sanitization methods, risk assessments, '
          'device capabilities, NIST standards, and verification results.\n\n'
          'Ask me a question or select one of the quick questions below.\n\n'
          '⚠️ All responses are advisory only. I do not execute sanitization operations '
          'or generate shell commands.',
      timestamp: DateTime.now(),
      targetSummary: 'None (general knowledge)',
    ));
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  AssistantContext _getCurrentContext(SanitizationController controller) {
    return AssistantContextBuilder.fromController(
      controller,
      overrideDevice: _assistantDevice,
      clearDevice: _deviceCleared,
    );
  }

  void _sendMessage(String text) {
    if (text.trim().isEmpty) return;

    final controller = context.read<SanitizationController>();
    final currentContext = _getCurrentContext(controller);

    setState(() {
      _messages.add(_ChatMessage(
        isUser: true,
        text: text.trim(),
        timestamp: DateTime.now(),
      ));
    });

    _inputController.clear();

    // Process with AI service using AssistantContext
    final response = _aiService.processQuery(text, context: currentContext);

    setState(() {
      _messages.add(_ChatMessage(
        isUser: false,
        text: response.answer,
        timestamp: DateTime.now(),
        response: response,
        targetSummary: currentContext.targetSummary,
      ));
    });

    // Scroll to bottom
    Future.delayed(const Duration(milliseconds: 100), () {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  void _showDeviceSelector(BuildContext context, SanitizationController controller) {
    final devices = controller.devices;

    showModalBottomSheet<void>(
      context: context,
      backgroundColor: AppTheme.surfaceDark,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (bottomSheetContext) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Text(
                          'Select Assistant Context Drive',
                          style: GoogleFonts.outfit(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: AppTheme.textPrimary,
                          ),
                        ),
                      ),
                      TextButton(
                        onPressed: () {
                          // Clear selection without altering controller
                          setState(() {
                            _deviceCleared = true;
                            _assistantDevice = null;
                          });
                          Navigator.pop(bottomSheetContext);
                        },
                        child: const Text('Clear Context', style: TextStyle(color: AppTheme.accentRose)),
                      ),
                    ],
                  ),
                ),
                const Divider(color: AppTheme.surfaceBorder),
                if (devices.isEmpty)
                  const Padding(
                    padding: EdgeInsets.all(20),
                    child: Text('No drives currently detected.', style: TextStyle(color: AppTheme.textMuted)),
                  )
                else
                  Flexible(
                    child: ListView.builder(
                      shrinkWrap: true,
                      itemCount: devices.length,
                      itemBuilder: (context, index) {
                        final d = devices[index];
                        final isSelected = !_deviceCleared &&
                            ((_assistantDevice != null && _assistantDevice!.stableId == d.stableId) ||
                             (_assistantDevice == null && controller.selectedDevice?.stableId == d.stableId));

                        return ListTile(
                          leading: Icon(
                            d.isFlashMedia ? Icons.flash_on : Icons.storage,
                            color: isSelected ? AppTheme.accentGold : AppTheme.textSecondary,
                          ),
                          title: Text(d.name, style: const TextStyle(color: AppTheme.textPrimary)),
                          subtitle: Text(
                            '${d.formattedCapacity} • ${d.busType}',
                            style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                          ),
                          trailing: isSelected ? const Icon(Icons.check, color: AppTheme.accentGold) : null,
                          onTap: () {
                            // Update assistant context only — never mutate controller.selectedDevice
                            setState(() {
                              _assistantDevice = d;
                              _deviceCleared = false;
                            });
                            Navigator.pop(bottomSheetContext);
                          },
                        );
                      },
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final currentContext = _getCurrentContext(controller);

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Column(
          children: [
            // Header with interactive context chip
            _buildHeader(currentContext, controller),

            // Chat messages
            Expanded(
              child: ListView.builder(
                controller: _scrollController,
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                itemCount: _messages.length,
                itemBuilder: (context, index) => _buildMessageBubble(_messages[index]),
              ),
            ),

            // Quick questions
            if (_messages.length < 5)
              _buildQuickQuestions(currentContext),

            // Input bar
            _buildInputBar(),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(AssistantContext contextSnapshot, SanitizationController controller) {
    final bool isDisconnected = contextSnapshot.isDisconnected;
    final bool hasDevice = contextSnapshot.hasDevice;

    String chipLabel;
    Color chipColor;
    IconData chipIcon;

    if (isDisconnected) {
      chipLabel = '${contextSnapshot.deviceName} (disconnected)';
      chipColor = AppTheme.accentRose;
      chipIcon = Icons.link_off;
    } else if (hasDevice) {
      final name = contextSnapshot.deviceName!;
      chipLabel = name.length > 20 ? '${name.substring(0, 20)}...' : name;
      chipColor = AppTheme.accentGold;
      chipIcon = Icons.storage;
    } else {
      chipLabel = 'No device selected';
      chipColor = AppTheme.textMuted;
      chipIcon = Icons.help_outline;
    }

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(bottom: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppTheme.accentBlue.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(Icons.psychology, color: AppTheme.accentBlue, size: 24),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'AI Assistant',
                  style: GoogleFonts.outfit(
                    color: AppTheme.textPrimary,
                    fontSize: 20,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                Text(
                  'Advisory-only • Does not execute operations',
                  style: GoogleFonts.inter(
                    color: AppTheme.textMuted,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          InkWell(
            key: const Key('assistant_context_chip'),
            onTap: () => _showDeviceSelector(context, controller),
            borderRadius: BorderRadius.circular(8),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: chipColor.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: chipColor.withValues(alpha: 0.3)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(chipIcon, color: chipColor, size: 14),
                  const SizedBox(width: 6),
                  Text(
                    chipLabel,
                    style: GoogleFonts.inter(
                      color: chipColor,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(width: 4),
                  Icon(Icons.arrow_drop_down, color: chipColor, size: 16),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMessageBubble(_ChatMessage msg) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: msg.isUser ? MainAxisAlignment.end : MainAxisAlignment.start,
        children: [
          if (!msg.isUser) ...[
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppTheme.accentBlue.withValues(alpha: 0.15),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.psychology, color: AppTheme.accentBlue, size: 18),
            ),
            const SizedBox(width: 10),
          ],
          Flexible(
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: msg.isUser
                    ? AppTheme.accentGold.withValues(alpha: 0.12)
                    : AppTheme.surfaceDark,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(16),
                  topRight: const Radius.circular(16),
                  bottomLeft: Radius.circular(msg.isUser ? 16 : 4),
                  bottomRight: Radius.circular(msg.isUser ? 4 : 16),
                ),
                border: Border.all(
                  color: msg.isUser
                      ? AppTheme.accentGold.withValues(alpha: 0.3)
                      : AppTheme.surfaceBorder,
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Target summary badge (Amendment 5)
                  if (!msg.isUser && msg.targetSummary != null) ...[
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.info_outline, size: 11, color: AppTheme.textMuted),
                        const SizedBox(width: 4),
                        Text(
                          'Answered for: ${msg.targetSummary}',
                          style: GoogleFonts.inter(
                            color: AppTheme.textMuted,
                            fontSize: 10,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                  ],
                  SelectableText(
                    msg.text,
                    style: GoogleFonts.inter(
                      color: AppTheme.textPrimary,
                      fontSize: 13,
                      height: 1.5,
                    ),
                  ),
                  if (msg.response != null) ...[
                    const SizedBox(height: 12),
                    _buildResponseMeta(msg.response!),
                  ],
                ],
              ),
            ),
          ),
          if (msg.isUser) ...[
            const SizedBox(width: 10),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.15),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.person, color: AppTheme.accentGold, size: 18),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildResponseMeta(AiResponse response) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Divider(color: AppTheme.surfaceBorder, height: 1),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 6,
          children: [
            if (response.recommendedMethod != null)
              _metaBadge('Method', response.recommendedMethod!, AppTheme.accentBlue),
            if (response.riskLevel != null)
              _metaBadge('Risk', response.riskLevel!, _getRiskColor(response.riskLevel!)),
            if (response.isSimulated)
              _metaBadge('Mode', 'Simulated', AppTheme.accentGold),
            if (response.researchBasis != null)
              _metaBadge('Research', 'See basis', AppTheme.accentEmerald),
          ],
        ),
        if (response.warnings.isNotEmpty) ...[
          const SizedBox(height: 10),
          ...response.warnings.map((w) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.warning_amber, color: AppTheme.accentOrange, size: 14),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        w,
                        style: GoogleFonts.inter(
                          color: AppTheme.accentOrange,
                          fontSize: 11,
                        ),
                      ),
                    ),
                  ],
                ),
              )),
        ],
        if (response.researchBasis != null) ...[
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppTheme.surfaceCard,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.science, color: AppTheme.accentEmerald, size: 14),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    response.researchBasis!,
                    style: GoogleFonts.inter(
                      color: AppTheme.textSecondary,
                      fontSize: 11,
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _metaBadge(String label, String value, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(
        '$label: $value',
        style: GoogleFonts.inter(
          color: color,
          fontSize: 10,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }

  Color _getRiskColor(String level) {
    switch (level.toUpperCase()) {
      case 'LOW':
        return AppTheme.accentEmerald;
      case 'MEDIUM':
        return AppTheme.accentGold;
      case 'HIGH':
        return AppTheme.accentOrange;
      case 'CRITICAL':
        return AppTheme.accentRose;
      default:
        return AppTheme.textMuted;
    }
  }

  Widget _buildQuickQuestions(AssistantContext contextSnapshot) {
    final questions = contextSnapshot.quickQuestions;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'QUICK QUESTIONS',
            style: GoogleFonts.inter(
              color: AppTheme.textMuted,
              fontSize: 10,
              fontWeight: FontWeight.w700,
              letterSpacing: 1,
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 6,
            children: questions.map((q) => ActionChip(
                  label: Text(
                    q,
                    style: GoogleFonts.inter(
                      fontSize: 11,
                      color: AppTheme.textSecondary,
                    ),
                  ),
                  backgroundColor: AppTheme.surfaceCard,
                  side: const BorderSide(color: AppTheme.surfaceBorder),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(20),
                  ),
                  onPressed: () => _sendMessage(q),
                )).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: const BoxDecoration(
        color: AppTheme.surfaceDark,
        border: Border(top: BorderSide(color: AppTheme.surfaceBorder)),
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _inputController,
              decoration: InputDecoration(
                hintText: 'Ask about sanitization, risk, verification...',
                hintStyle: GoogleFonts.inter(color: AppTheme.textMuted, fontSize: 13),
                filled: true,
                fillColor: AppTheme.surfaceCard,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: AppTheme.surfaceBorder),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: AppTheme.surfaceBorder),
                ),
                contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              ),
              style: GoogleFonts.inter(color: AppTheme.textPrimary, fontSize: 13),
              onSubmitted: _sendMessage,
            ),
          ),
          const SizedBox(width: 10),
          Container(
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [AppTheme.accentGold, AppTheme.accentGoldLight],
              ),
              borderRadius: BorderRadius.circular(12),
            ),
            child: IconButton(
              icon: const Icon(Icons.send, color: Colors.white, size: 20),
              onPressed: () => _sendMessage(_inputController.text),
            ),
          ),
        ],
      ),
    );
  }
}

class _ChatMessage {
  final bool isUser;
  final String text;
  final DateTime timestamp;
  final AiResponse? response;
  final String? targetSummary;

  const _ChatMessage({
    required this.isUser,
    required this.text,
    required this.timestamp,
    this.response,
    this.targetSummary,
  });
}
