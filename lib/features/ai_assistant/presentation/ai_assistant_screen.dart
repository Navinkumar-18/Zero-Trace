import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../../../models/device_profile.dart';
import '../../../services/ai_service.dart';
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

  static const List<String> _quickQuestions = [
    'Why is overwrite not recommended for SSDs?',
    'What sanitization method is recommended?',
    'What does cryptographic erase mean?',
    'Explain NIST SP 800-88 categories',
    'Why is this device high risk?',
    'What is the Flash Translation Layer?',
    'Explain CLEAR vs PURGE',
    'What are HPA/DCO hidden sectors?',
    'Why did verification fail?',
    'Explain this certificate',
  ];

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
    ));
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _sendMessage(String text) {
    if (text.trim().isEmpty) return;

    final controller = context.read<SanitizationController>();
    final device = controller.selectedDevice;

    setState(() {
      _messages.add(_ChatMessage(
        isUser: true,
        text: text.trim(),
        timestamp: DateTime.now(),
      ));
    });

    _inputController.clear();

    // Process with AI service
    final response = _aiService.processQuery(text, device: device);

    setState(() {
      _messages.add(_ChatMessage(
        isUser: false,
        text: response.answer,
        timestamp: DateTime.now(),
        response: response,
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

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final device = controller.selectedDevice;

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Column(
          children: [
            // Header
            _buildHeader(device),

            // Chat messages
            Expanded(
              child: ListView.builder(
                controller: _scrollController,
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                itemCount: _messages.length,
                itemBuilder: (context, index) => _buildMessageBubble(_messages[index]),
              ),
            ),

            // Quick questions (show when few messages)
            if (_messages.length < 4)
              _buildQuickQuestions(),

            // Input bar
            _buildInputBar(),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(DeviceProfile? device) {
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
          if (device != null)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AppTheme.accentGold.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.accentGold.withValues(alpha: 0.3)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.storage, color: AppTheme.accentGold, size: 14),
                  const SizedBox(width: 6),
                  Text(
                    device.name.length > 20
                        ? '${device.name.substring(0, 20)}...'
                        : device.name,
                    style: GoogleFonts.inter(
                      color: AppTheme.accentGold,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
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

  Widget _buildQuickQuestions() {
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
            children: _quickQuestions.map((q) => ActionChip(
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

  const _ChatMessage({
    required this.isUser,
    required this.text,
    required this.timestamp,
    this.response,
  });
}
