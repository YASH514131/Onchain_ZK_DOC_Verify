/// Home screen: entry point with navigation to main flows.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../providers/providers.dart';
import '../ui/theme.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final walletProv = context.watch<WalletProvider>();

    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 32),
              // ── Title ──
              Text(
                'ZK-DocAuth',
                style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                  fontSize: 36,
                  fontWeight: FontWeight.w800,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                'Zero Knowledge Document Authentication on Solana',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  color: AppTheme.primaryColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Text(
                  'Devnet',
                  style: TextStyle(
                    color: AppTheme.primaryColor,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),

              const SizedBox(height: 24),

              // ── Wallet Card ──
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: AppTheme.gradientCard,
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
                          size: 22,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          walletProv.isInitialized
                              ? 'Wallet Connected'
                              : walletProv.isLoading
                              ? 'Connecting...'
                              : 'Wallet Not Connected',
                          style: TextStyle(
                            fontWeight: FontWeight.w600,
                            color: walletProv.isInitialized
                                ? AppTheme.successColor
                                : Colors.orange,
                          ),
                        ),
                        const Spacer(),
                        if (walletProv.isInitialized)
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 3,
                            ),
                            decoration: BoxDecoration(
                              color: AppTheme.successColor.withValues(
                                alpha: 0.15,
                              ),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              '${walletProv.balanceSol.toStringAsFixed(4)} SOL',
                              style: const TextStyle(
                                fontWeight: FontWeight.w700,
                                fontFamily: 'monospace',
                                fontSize: 13,
                                color: AppTheme.successColor,
                              ),
                            ),
                          ),
                      ],
                    ),
                    if (walletProv.publicKey != null) ...[
                      const SizedBox(height: 10),
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
                    if (walletProv.isInitialized) ...[
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          OutlinedButton.icon(
                            onPressed: walletProv.isLoading
                                ? null
                                : () => walletProv.refreshBalance(),
                            icon: const Icon(Icons.refresh, size: 16),
                            label: const Text('Refresh'),
                            style: OutlinedButton.styleFrom(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 6,
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          OutlinedButton.icon(
                            onPressed: walletProv.isLoading
                                ? null
                                : () => walletProv.requestAirdrop(amount: 1.0),
                            icon: const Icon(Icons.air, size: 16),
                            label: const Text('Airdrop 1 SOL'),
                            style: OutlinedButton.styleFrom(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 6,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                    if (walletProv.errorMessage != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        walletProv.errorMessage!,
                        style: TextStyle(
                          color: AppTheme.errorColor,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ],
                ),
              ),

              const SizedBox(height: 24),

              // ── Feature Cards ──
              _FeatureCard(
                icon: Icons.badge_outlined,
                title: 'Issue Credential',
                description:
                    'Create a verifiable credential from KYC document data '
                    'and compute its Poseidon hash commitment.',
                onTap: () => Navigator.pushNamed(context, '/credential'),
              ),
              const SizedBox(height: 16),
              _FeatureCard(
                icon: Icons.verified_user_outlined,
                title: 'Generate ZK Proof',
                description:
                    'Prove a property (age, nationality, validity) of your '
                    'credential without revealing the underlying data.',
                onTap: () => Navigator.pushNamed(context, '/proof'),
              ),
              const SizedBox(height: 16),
              _FeatureCard(
                icon: Icons.account_balance_outlined,
                title: 'On-Chain Verification',
                description:
                    'Submit the Groth16 proof to the Solana program for '
                    'trustless on-chain verification via alt_bn128 pairings.',
                onTap: () => Navigator.pushNamed(context, '/verify'),
              ),
              const SizedBox(height: 16),
              _FeatureCard(
                icon: Icons.account_tree_outlined,
                title: 'Merkle Tree Explorer',
                description:
                    'Inspect the credential Merkle tree, view roots, '
                    'generate inclusion proofs, and manage revocations.',
                onTap: () => Navigator.pushNamed(context, '/merkle'),
              ),

              const SizedBox(height: 40),

              // ── Protocol Summary ──
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: AppTheme.gradientCard,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Protocol Summary',
                      style: Theme.of(
                        context,
                      ).textTheme.headlineMedium?.copyWith(fontSize: 16),
                    ),
                    const SizedBox(height: 12),
                    const _ProtocolStep(
                      number: '1',
                      label: 'Issuer verifies document off-chain',
                    ),
                    const _ProtocolStep(
                      number: '2',
                      label: 'Credential hash inserted into Merkle tree',
                    ),
                    const _ProtocolStep(
                      number: '3',
                      label: 'Merkle root published to Solana',
                    ),
                    const _ProtocolStep(
                      number: '4',
                      label: 'User generates Groth16 proof locally',
                    ),
                    const _ProtocolStep(
                      number: '5',
                      label: 'Proof verified on-chain via pairing check',
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),
              Center(
                child: Text(
                  'Built for privacy-first digital identity on Solana.',
                  style: Theme.of(context).textTheme.bodySmall,
                  textAlign: TextAlign.center,
                ),
              ),
              const SizedBox(height: 16),
            ],
          ),
        ),
      ),
    );
  }
}

class _FeatureCard extends StatelessWidget {
  const _FeatureCard({
    required this.icon,
    required this.title,
    required this.description,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String description;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: AppTheme.gradientCard,
        child: Row(
          children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: AppTheme.primaryColor.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(icon, color: AppTheme.primaryColor, size: 26),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    description,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Colors.white24),
          ],
        ),
      ),
    );
  }
}

class _ProtocolStep extends StatelessWidget {
  const _ProtocolStep({required this.number, required this.label});

  final String number;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(
              color: AppTheme.primaryColor.withValues(alpha: 0.2),
              shape: BoxShape.circle,
            ),
            alignment: Alignment.center,
            child: Text(
              number,
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: AppTheme.primaryColor,
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(label, style: Theme.of(context).textTheme.bodyMedium),
          ),
        ],
      ),
    );
  }
}
