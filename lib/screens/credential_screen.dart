/// Credential issuance screen.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/constants.dart';
import '../providers/providers.dart';
import '../ui/theme.dart';
import '../ui/widgets.dart';

class CredentialScreen extends StatefulWidget {
  const CredentialScreen({super.key});

  @override
  State<CredentialScreen> createState() => _CredentialScreenState();
}

class _CredentialScreenState extends State<CredentialScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameCtrl = TextEditingController();
  final _dobCtrl = TextEditingController(text: '20040315');
  final _docIdCtrl = TextEditingController();
  final _expiryCtrl = TextEditingController(text: '20350101');
  final _issuerCtrl = TextEditingController(
    text: AppConstants.programId, // Placeholder issuer key.
  );

  String _selectedNationality = 'India';

  @override
  void dispose() {
    _nameCtrl.dispose();
    _dobCtrl.dispose();
    _docIdCtrl.dispose();
    _expiryCtrl.dispose();
    _issuerCtrl.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;

    final provider = context.read<CredentialProvider>();
    provider.issueCredential(
      name: _nameCtrl.text.trim(),
      dob: int.parse(_dobCtrl.text.trim()),
      nationality: _selectedNationality,
      nationalityCode: AppConstants.countryCodes[_selectedNationality] ?? 356,
      documentId: _docIdCtrl.text.trim(),
      expiry: int.parse(_expiryCtrl.text.trim()),
      issuerPublicKey: _issuerCtrl.text.trim(),
    );

    if (provider.hasCredential && provider.commitment != null) {
      // Insert into Merkle tree via ProofProvider.
      final proofProv = context.read<ProofProvider>();
      final leafIndex = proofProv.insertCredential(provider.commitment!);
      provider.credential!.leafIndex = leafIndex;

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Credential issued. Leaf index: $leafIndex'),
          backgroundColor: AppTheme.successColor,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final provider = context.watch<CredentialProvider>();

    return Scaffold(
      appBar: AppBar(title: const Text('Issue Credential')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionHeader(title: 'Document Fields'),

              // Name
              TextFormField(
                controller: _nameCtrl,
                decoration: const InputDecoration(labelText: 'Full Name'),
                validator: (v) =>
                    (v == null || v.trim().isEmpty) ? 'Required' : null,
              ),
              const SizedBox(height: 14),

              // DOB
              TextFormField(
                controller: _dobCtrl,
                decoration: const InputDecoration(
                  labelText: 'Date of Birth (YYYYMMDD)',
                ),
                keyboardType: TextInputType.number,
                validator: (v) {
                  if (v == null || v.trim().isEmpty) return 'Required';
                  final n = int.tryParse(v.trim());
                  if (n == null || n < 19000101 || n > 20260101) {
                    return 'Invalid date';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 14),

              // Nationality
              DropdownButtonFormField<String>(
                value: _selectedNationality,
                decoration: const InputDecoration(labelText: 'Nationality'),
                items: AppConstants.countryCodes.keys
                    .map((c) => DropdownMenuItem(value: c, child: Text(c)))
                    .toList(),
                onChanged: (v) {
                  if (v != null) setState(() => _selectedNationality = v);
                },
              ),
              const SizedBox(height: 14),

              // Document ID
              TextFormField(
                controller: _docIdCtrl,
                decoration: const InputDecoration(
                  labelText: 'Document ID (Passport / NID)',
                ),
                validator: (v) =>
                    (v == null || v.trim().isEmpty) ? 'Required' : null,
              ),
              const SizedBox(height: 14),

              // Expiry
              TextFormField(
                controller: _expiryCtrl,
                decoration: const InputDecoration(
                  labelText: 'Expiry Date (YYYYMMDD)',
                ),
                keyboardType: TextInputType.number,
                validator: (v) {
                  if (v == null || v.trim().isEmpty) return 'Required';
                  final n = int.tryParse(v.trim());
                  if (n == null || n < 20260101) return 'Document expired';
                  return null;
                },
              ),
              const SizedBox(height: 14),

              // Issuer pubkey
              TextFormField(
                controller: _issuerCtrl,
                decoration: const InputDecoration(
                  labelText: 'Issuer Public Key (Base58)',
                ),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                validator: (v) =>
                    (v == null || v.trim().length < 32) ? 'Invalid key' : null,
              ),
              const SizedBox(height: 24),

              // Submit
              LoadingButton(
                label: 'Issue Credential',
                icon: Icons.badge_outlined,
                isLoading: provider.isLoading,
                onPressed: _submit,
              ),

              // Error
              if (provider.errorMessage != null) ...[
                const SizedBox(height: 16),
                Text(
                  provider.errorMessage!,
                  style: TextStyle(color: AppTheme.errorColor),
                ),
              ],

              // Result
              if (provider.hasCredential && provider.commitment != null) ...[
                const SectionHeader(title: 'Credential Commitment'),
                HashDisplay(
                  label: 'Poseidon Hash (credential_hash)',
                  hash: '0x${provider.commitment!.toRadixString(16)}',
                ),
                const SizedBox(height: 8),
                InfoRow(
                  label: 'Leaf Index',
                  value: '${provider.credential!.leafIndex ?? "N/A"}',
                ),
                InfoRow(
                  label: 'Merkle Root',
                  value:
                      '0x${context.read<ProofProvider>().merkleRoot.toRadixString(16).substring(0, 16)}...',
                  isMonospace: true,
                ),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: () => Navigator.pushNamed(context, '/proof'),
                  icon: const Icon(Icons.arrow_forward),
                  label: const Text('Generate ZK Proof'),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
