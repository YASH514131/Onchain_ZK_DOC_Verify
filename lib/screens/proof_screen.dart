/// ZK Proof generation screen.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../providers/providers.dart';
import '../services/proof_service.dart';
import '../ui/theme.dart';
import '../ui/widgets.dart';

class ProofScreen extends StatefulWidget {
  const ProofScreen({super.key});

  @override
  State<ProofScreen> createState() => _ProofScreenState();
}

class _ProofScreenState extends State<ProofScreen> {
  ClaimType _selectedClaim = ClaimType.ageAbove;
  final _minAgeCtrl = TextEditingController(text: '18');
  int? _selectedNationalityCode = 356;

  @override
  void dispose() {
    _minAgeCtrl.dispose();
    super.dispose();
  }

  Future<void> _generate() async {
    final credProv = context.read<CredentialProvider>();
    final proofProv = context.read<ProofProvider>();

    if (!credProv.hasCredential) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Issue a credential first')));
      return;
    }

    final credential = credProv.credential!;
    final leafIndex = credential.leafIndex;

    if (leafIndex == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Credential not inserted into Merkle tree'),
        ),
      );
      return;
    }

    // Prepare Merkle proof.
    proofProv.prepareMerkleProof(leafIndex);

    if (proofProv.errorMessage != null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(proofProv.errorMessage!)));
      return;
    }

    // Generate proof.
    await proofProv.generateProof(
      credential: credential,
      claimType: _selectedClaim,
      minAge: _selectedClaim == ClaimType.ageAbove
          ? int.tryParse(_minAgeCtrl.text) ?? 18
          : null,
      expectedNationalityCode: _selectedClaim == ClaimType.nationalityEquals
          ? _selectedNationalityCode
          : null,
    );
  }

  @override
  Widget build(BuildContext context) {
    final credProv = context.watch<CredentialProvider>();
    final proofProv = context.watch<ProofProvider>();

    return Scaffold(
      appBar: AppBar(title: const Text('Generate ZK Proof')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Credential Status ──
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: AppTheme.gradientCard,
              child: Row(
                children: [
                  Icon(
                    credProv.hasCredential ? Icons.check_circle : Icons.cancel,
                    color: credProv.hasCredential
                        ? AppTheme.successColor
                        : AppTheme.errorColor,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      credProv.hasCredential
                          ? 'Credential loaded: ${credProv.credential!.name}'
                          : 'No credential loaded. Issue one first.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ),
                  if (!credProv.hasCredential)
                    TextButton(
                      onPressed: () =>
                          Navigator.pushNamed(context, '/credential'),
                      child: const Text('Issue'),
                    ),
                ],
              ),
            ),

            const SectionHeader(title: 'Claim Type'),

            // ── Claim selector ──
            ...ClaimType.values.map(
              (ct) => RadioListTile<ClaimType>(
                value: ct,
                groupValue: _selectedClaim,
                onChanged: (v) => setState(() => _selectedClaim = v!),
                title: Text(_claimLabel(ct)),
                dense: true,
                activeColor: AppTheme.primaryColor,
              ),
            ),

            // ── Claim parameters ──
            if (_selectedClaim == ClaimType.ageAbove) ...[
              const SizedBox(height: 12),
              TextFormField(
                controller: _minAgeCtrl,
                decoration: const InputDecoration(labelText: 'Minimum Age'),
                keyboardType: TextInputType.number,
              ),
            ],
            if (_selectedClaim == ClaimType.nationalityEquals) ...[
              const SizedBox(height: 12),
              DropdownButtonFormField<int>(
                value: _selectedNationalityCode,
                decoration: const InputDecoration(
                  labelText: 'Expected Nationality Code',
                ),
                items: const [
                  DropdownMenuItem(value: 356, child: Text('India (356)')),
                  DropdownMenuItem(value: 840, child: Text('USA (840)')),
                  DropdownMenuItem(value: 826, child: Text('UK (826)')),
                  DropdownMenuItem(value: 276, child: Text('Germany (276)')),
                ],
                onChanged: (v) => setState(() => _selectedNationalityCode = v),
              ),
            ],

            const SizedBox(height: 24),

            // ── Generate button ──
            LoadingButton(
              label: 'Generate Groth16 Proof',
              icon: Icons.lock_outline,
              isLoading: proofProv.isGenerating,
              onPressed: credProv.hasCredential ? _generate : null,
            ),

            // ── Error ──
            if (proofProv.errorMessage != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: AppTheme.errorColor.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(Icons.error_outline, color: AppTheme.errorColor),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        proofProv.errorMessage!,
                        style: TextStyle(color: AppTheme.errorColor),
                      ),
                    ),
                  ],
                ),
              ),
            ],

            // ── Proof Result ──
            if (proofProv.proofOutput != null) ...[
              const SectionHeader(title: 'Proof Generated'),
              StatusBadge(
                label: proofProv.proofOutput!.witnessValid
                    ? 'CONSTRAINTS SATISFIED'
                    : 'INVALID WITNESS',
                isSuccess: proofProv.proofOutput!.witnessValid,
              ),
              const SizedBox(height: 16),

              if (proofProv.proofGenerationTime != null)
                InfoRow(
                  label: 'Generation Time',
                  value: '${proofProv.proofGenerationTime!.inMilliseconds} ms',
                ),

              const SizedBox(height: 8),
              HashDisplay(
                label: 'Proof.A (G1)',
                hash: '0x${proofProv.proofOutput!.proof.a.x.toRadixString(16)}',
              ),
              HashDisplay(
                label: 'Proof.B (G2)',
                hash:
                    '0x${proofProv.proofOutput!.proof.b.xC0.toRadixString(16)}',
              ),
              HashDisplay(
                label: 'Proof.C (G1)',
                hash: '0x${proofProv.proofOutput!.proof.c.x.toRadixString(16)}',
              ),

              const SizedBox(height: 12),
              HashDisplay(
                label: 'Public Input: Merkle Root',
                hash:
                    '0x${proofProv.proofOutput!.publicInputs.merkleRoot.toRadixString(16)}',
              ),
              InfoRow(
                label: 'Public Input: Date',
                value: '${proofProv.proofOutput!.publicInputs.currentDate}',
              ),
              InfoRow(
                label: 'Public Input: Min Age',
                value: '${proofProv.proofOutput!.publicInputs.minAge}',
              ),

              const SizedBox(height: 24),
              OutlinedButton.icon(
                onPressed: () => Navigator.pushNamed(context, '/verify'),
                icon: const Icon(Icons.send_outlined),
                label: const Text('Submit to Solana'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _claimLabel(ClaimType ct) {
    return switch (ct) {
      ClaimType.ageAbove => 'Age >= N',
      ClaimType.nationalityEquals => 'Nationality == X',
      ClaimType.documentNotExpired => 'Document Not Expired',
      ClaimType.credentialValid => 'Credential Valid (Merkle inclusion)',
      ClaimType.nameHashEquals => 'Name Hash Matches',
    };
  }
}
