/// Merkle tree explorer screen.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/constants.dart';
import '../providers/providers.dart';
import '../ui/theme.dart';
import '../ui/widgets.dart';

class MerkleScreen extends StatelessWidget {
  const MerkleScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final proofProv = context.watch<ProofProvider>();

    return Scaffold(
      appBar: AppBar(title: const Text('Merkle Tree Explorer')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Tree Overview ──
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: AppTheme.gradientCard,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Binary Merkle Tree',
                    style: Theme.of(context).textTheme.headlineMedium,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Poseidon hash, fixed depth',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 16),
                  InfoRow(
                    label: 'Depth',
                    value: '${AppConstants.merkleTreeDepth}',
                  ),
                  InfoRow(
                    label: 'Max Leaves',
                    value: '${AppConstants.maxLeaves}',
                  ),
                  InfoRow(
                    label: 'Current Leaves',
                    value: '${proofProv.treeSize}',
                  ),
                  InfoRow(
                    label: 'Hash Function',
                    value: 'Poseidon (t=3, BN254)',
                  ),
                ],
              ),
            ),

            const SectionHeader(title: 'Current Root'),
            HashDisplay(
              label: 'Merkle Root',
              hash: '0x${proofProv.merkleRoot.toRadixString(16)}',
            ),

            const SectionHeader(title: 'Tree Structure'),

            // ── ASCII Diagram ──
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(12),
              ),
              child: const SelectableText(
                '              root\n'
                '             /    \\\n'
                '           H01    H23\n'
                '          /  \\   /  \\\n'
                '        H0   H1 H2  H3\n'
                '       /  \\ / \\ / \\ / \\\n'
                '      L0 L1 L2 L3 L4 L5 L6 L7\n'
                '\n'
                '  H_i = Poseidon(left, right)\n'
                '  L_i = credential_hash (leaf)\n'
                '  Empty leaves = 0',
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: Colors.white60,
                  height: 1.5,
                ),
              ),
            ),

            const SectionHeader(title: 'Proof Verification'),

            if (proofProv.merkleProof != null) ...[
              StatusBadge(label: 'PROOF AVAILABLE', isSuccess: true),
              const SizedBox(height: 12),
              InfoRow(
                label: 'Leaf',
                value:
                    '0x${proofProv.merkleProof!.leaf.toRadixString(16).substring(0, 16)}...',
                isMonospace: true,
              ),
              InfoRow(
                label: 'Path Length',
                value: '${proofProv.merkleProof!.pathElements.length}',
              ),
              InfoRow(
                label: 'Path Indices',
                value:
                    '${proofProv.merkleProof!.pathIndices.take(8).map((i) => '$i').join(', ')}...',
              ),
              const SizedBox(height: 12),
              ...proofProv.merkleProof!.pathElements
                  .take(5)
                  .toList()
                  .asMap()
                  .entries
                  .map(
                    (e) => HashDisplay(
                      label: 'Sibling[${e.key}]',
                      hash: '0x${e.value.toRadixString(16)}',
                    ),
                  ),
              if (proofProv.merkleProof!.pathElements.length > 5)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Text(
                    '... and ${proofProv.merkleProof!.pathElements.length - 5} more siblings',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ),
            ] else
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  'No Merkle proof generated yet.\n'
                  'Issue a credential and generate a proof to see path details.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),

            const SectionHeader(title: 'Complexity'),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.black26,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: const [
                  InfoRow(label: 'Proof Size', value: 'O(log n) = 20 siblings'),
                  InfoRow(label: 'Proof Bytes', value: '20 * 32 = 640 bytes'),
                  InfoRow(
                    label: 'In-Circuit Cost',
                    value: '20 Poseidon hashes = ~5,000 constraints',
                  ),
                  InfoRow(
                    label: 'On-Chain Cost',
                    value: 'O(1) -- verified inside Groth16 proof',
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
