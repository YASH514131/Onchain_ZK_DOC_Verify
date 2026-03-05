import 'package:flutter_test/flutter_test.dart';

import 'package:zk_doc_auth/main.dart';

void main() {
  testWidgets('App renders home screen', (WidgetTester tester) async {
    await tester.pumpWidget(const ZKDocAuthApp());
    await tester.pumpAndSettle();

    // Verify the app title is shown.
    expect(find.text('ZK-DocAuth'), findsOneWidget);
  });
}
