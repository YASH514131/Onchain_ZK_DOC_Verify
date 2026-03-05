import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'providers/providers.dart';
import 'screens/credential_screen.dart';
import 'screens/home_screen.dart';
import 'screens/merkle_screen.dart';
import 'screens/proof_screen.dart';
import 'screens/verify_screen.dart';
import 'ui/theme.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ZKDocAuthApp());
}

class ZKDocAuthApp extends StatelessWidget {
  const ZKDocAuthApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(
          create: (_) {
            final wallet = WalletProvider();
            wallet.initialize(); // Fire-and-forget; UI reacts to state changes.
            return wallet;
          },
        ),
        ChangeNotifierProvider(create: (_) => CredentialProvider()),
        ChangeNotifierProvider(create: (_) => ProofProvider()),
        ChangeNotifierProvider(create: (_) => SolanaProvider()),
      ],
      child: MaterialApp(
        title: 'ZK-DocAuth Solana',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.darkTheme,
        initialRoute: '/',
        routes: {
          '/': (_) => const HomeScreen(),
          '/credential': (_) => const CredentialScreen(),
          '/proof': (_) => const ProofScreen(),
          '/verify': (_) => const VerifyScreen(),
          '/merkle': (_) => const MerkleScreen(),
        },
      ),
    );
  }
}
