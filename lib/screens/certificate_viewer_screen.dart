import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:printing/printing.dart';
import 'package:provider/provider.dart';

import '../services/sanitization_controller.dart';
import '../widgets/theme.dart';

class CertificateViewerScreen extends StatefulWidget {
  const CertificateViewerScreen({super.key});

  @override
  State<CertificateViewerScreen> createState() => _CertificateViewerScreenState();
}

class _CertificateViewerScreenState extends State<CertificateViewerScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = context.watch<SanitizationController>();
    final cert = controller.completedCertificate;

    if (cert == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Audit Certificate')),
        body: const Center(child: Text('No certificate generated.')),
      );
    }

    final certJsonStr = const JsonEncoder.withIndent('  ').convert(cert.toJson());

    return Scaffold(
      appBar: AppBar(
        title: Text('Certificate: ${cert.certificateId}'),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.accentGold,
          labelColor: AppTheme.accentGold,
          unselectedLabelColor: AppTheme.textSecondary,
          tabs: const [
            Tab(icon: Icon(Icons.picture_as_pdf, size: 18), text: 'PDF Document'),
            Tab(icon: Icon(Icons.code, size: 18), text: 'Signed JSON'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          // Tab 1: Rendered PDF View
          FutureBuilder<Uint8List?>(
            future: controller.getPdfCertificateBytes(),
            builder: (context, snapshot) {
              if (snapshot.connectionState == ConnectionState.waiting) {
                return const Center(child: CircularProgressIndicator());
              }
              if (snapshot.hasError || snapshot.data == null) {
                return const Center(child: Text('Error rendering PDF preview'));
              }

              return PdfPreview(
                build: (format) => snapshot.data!,
                canChangeOrientation: false,
                canChangePageFormat: false,
                canDebug: false,
                pdfFileName: '${cert.certificateId}.pdf',
              );
            },
          ),

          // Tab 2: Raw Signed JSON View
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      'ECDSA P-256 AUDIT PAYLOAD',
                      style: TextStyle(color: AppTheme.accentGold, fontWeight: FontWeight.bold, fontSize: 12),
                    ),
                    ElevatedButton.icon(
                      icon: const Icon(Icons.copy, size: 16),
                      label: const Text('Copy JSON'),
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      ),
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: certJsonStr));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Certificate JSON copied to clipboard!')),
                        );
                      },
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Expanded(
                  child: Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: Colors.black,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppTheme.surfaceBorder),
                    ),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        certJsonStr,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: AppTheme.accentEmerald,
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      bottomNavigationBar: Container(
        padding: const EdgeInsets.all(16),
        decoration: const BoxDecoration(
          color: AppTheme.surfaceDark,
          border: Border(top: BorderSide(color: AppTheme.surfaceBorder)),
        ),
        child: OutlinedButton.icon(
          icon: const Icon(Icons.home),
          label: const Text('RETURN TO INVENTORY'),
          onPressed: () {
            context.go('/');
          },
        ),
      ),
    );
  }
}
