/// On-chain verification & submission screen.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../core/constants.dart';
import '../providers/providers.dart';
import '../ui/theme.dart';
import '../ui/widgets.dart';

class VerifyScreen extends StatelessWidget {
  const VerifyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final proofProv = context.watch<ProofProvider>();
    final solanaProv = context.watch<SolanaProvider>();
    final credProv = context.watch<CredentialProvider>();
    final walletProv = context.watch<WalletProvider>();

    final hasProof = proofProv.proofOutput != null;

    return Scaffold(
      appBar: AppBar(title: const Text('On-Chain Verification')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Wallet Status ──
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                color: walletProv.isInitialized
                    ? AppTheme.successColor.withValues(alpha: 0.08)
                    : Colors.orange.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: walletProv.isInitialized
                      ? AppTheme.successColor.withValues(alpha: 0.3)
                      : Colors.orange.withValues(alpha: 0.3),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        walletProv.isInitialized
                            ? Icons.account_balance_wallet
                            : Icons.account_balance_wallet_outlined,
                        color: walletProv.isInitialized
                            ? AppTheme.successColor
                            : Colors.orange,
                        size: 20,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        walletProv.isInitialized
                            ? 'Wallet Connected'
                            : 'Wallet Loading...',
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          color: walletProv.isInitialized
                              ? AppTheme.successColor
                              : Colors.orange,
                        ),
                      ),
                      const Spacer(),
                      if (walletProv.isInitialized)
                        Text(
                          '${walletProv.balanceSol.toStringAsFixed(4)} SOL',
                          style: const TextStyle(
                            fontWeight: FontWeight.w700,
                            fontFamily: 'monospace',
                          ),
                        ),
                    ],
                  ),
                  if (walletProv.publicKey != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      walletProv.publicKey!,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                        color: Colors.white54,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                  if (walletProv.errorMessage != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      walletProv.errorMessage!,
                      style: const TextStyle(
                        color: Colors.orange,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ],
              ),
            ),

            // ── Cluster Info ──
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: AppTheme.gradientCard,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 10,
                        height: 10,
                        decoration: const BoxDecoration(
                          color: AppTheme.successColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'Solana Devnet',
                        style: Theme.of(context).textTheme.bodyLarge,
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  InfoRow(
                    label: 'RPC Endpoint',
                    value: solanaProv.cluster,
                    isMonospace: true,
                  ),
                  InfoRow(
                    label: 'Program ID',
                    value:
                        '${AppConstants.programId.substring(0, 8)}...${AppConstants.programId.substring(AppConstants.programId.length - 8)}',
                    isMonospace: true,
                  ),
                  InfoRow(
                    label: 'Compute Budget',
                    value: '${AppConstants.verificationComputeUnits} CU',
                  ),
                  InfoRow(label: 'Est. Cost', value: '~0.0000054 SOL'),
                ],
              ),
            ),

            const SectionHeader(title: 'Proof Status'),

            // ── Proof check ──
            if (!hasProof)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: Colors.orange.withValues(alpha: 0.3),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.warning_amber, color: Colors.orange),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'No proof generated',
                            style: TextStyle(
                              fontWeight: FontWeight.w600,
                              color: Colors.orange,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Generate a ZK proof first before submitting to Solana.',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    TextButton(
                      onPressed: () => Navigator.pushNamed(context, '/proof'),
                      child: const Text('Generate'),
                    ),
                  ],
                ),
              )
            else ...[
              StatusBadge(label: 'PROOF READY', isSuccess: true),
              const SizedBox(height: 12),
              HashDisplay(
                label: 'Merkle Root',
                hash:
                    '0x${proofProv.proofOutput!.publicInputs.merkleRoot.toRadixString(16)}',
              ),
              InfoRow(
                label: 'Proof Size',
                value:
                    '${proofProv.proofOutput!.proof.serialize().length} bytes',
              ),
              InfoRow(
                label: 'Public Inputs',
                value: '4 field elements (128 bytes)',
              ),
            ],

            const SectionHeader(title: 'Verification Pipeline'),

            // ── Pipeline steps ──
            _PipelineStep(
              step: 1,
              label: 'Deserialize proof (A, B, C) and public inputs',
              isDone: hasProof,
            ),
            _PipelineStep(
              step: 2,
              label: 'Load IssuerAccount PDA, check merkle_root match',
              isDone: false,
            ),
            _PipelineStep(
              step: 3,
              label: 'Compute vk_x = IC[0] + sum(x_i * IC[i+1])',
              isDone: false,
            ),
            _PipelineStep(
              step: 4,
              label:
                  'Execute pairing check: e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta) == 1',
              isDone: false,
            ),
            _PipelineStep(
              step: 5,
              label: 'Emit ProofVerified event',
              isDone: solanaProv.transactionSignature != null,
            ),

            const SizedBox(height: 24),

            // ── Submit Button ──
            LoadingButton(
              label: 'Submit Proof to Solana',
              icon: Icons.send_outlined,
              isLoading: solanaProv.isSubmitting,
              onPressed: hasProof
                  ? () {
                      solanaProv.submitProof(
                        proofOutput: proofProv.proofOutput!,
                        issuerPubkey:
                            credProv.credential?.issuerPublicKey ??
                            AppConstants.programId,
                      );
                    }
                  : null,
            ),

            // ── Error ──
            if (solanaProv.errorMessage != null) ...[
              const SizedBox(height: 16),
              Text(
                solanaProv.errorMessage!,
                style: TextStyle(color: AppTheme.errorColor),
              ),
            ],

            // ── Success ──
            if (solanaProv.transactionSignature != null) ...[
              const SizedBox(height: 24),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: AppTheme.successColor.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: AppTheme.successColor.withValues(alpha: 0.3),
                  ),
                ),
                child: Column(
                  children: [
                    const Icon(
                      Icons.check_circle,
                      color: AppTheme.successColor,
                      size: 48,
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Proof Verified On-Chain',
                      style: Theme.of(context).textTheme.headlineMedium
                          ?.copyWith(color: AppTheme.successColor),
                    ),
                    const SizedBox(height: 12),
                    HashDisplay(
                      label: 'Transaction Signature',
                      hash: solanaProv.transactionSignature!,
                    ),
                    const SizedBox(height: 8),
                    TextButton.icon(
                      onPressed: () {
                        Clipboard.setData(
                          ClipboardData(text: solanaProv.transactionSignature!),
                        );
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Copied to clipboard')),
                        );
                      },
                      icon: const Icon(Icons.copy, size: 16),
                      label: const Text('Copy Signature'),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _PipelineStep extends StatelessWidget {
  const _PipelineStep({
    required this.step,
    required this.label,
    required this.isDone,
  });

  final int step;
  final String label;
  final bool isDone;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 28,
            height: 28,
            decoration: BoxDecoration(
              color: isDone
                  ? AppTheme.successColor.withValues(alpha: 0.2)
                  : Colors.white10,
              shape: BoxShape.circle,
            ),
            alignment: Alignment.center,
            child: isDone
                ? const Icon(
                    Icons.check,
                    size: 16,
                    color: AppTheme.successColor,
                  )
                : Text(
                    '$step',
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Colors.white54,
                    ),
                  ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              label,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: isDone ? AppTheme.successColor : Colors.white54,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
