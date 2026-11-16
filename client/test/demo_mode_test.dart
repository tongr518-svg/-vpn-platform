import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_platform_client/main.dart';

void main() {
  testWidgets('demo mode shows synthetic read-only account UI', (tester) async {
    await tester.pumpWidget(const VpnClientApp());
    await tester.pumpAndSettle();

    await tester.tap(find.text('进入演示模式'));
    await tester.pumpAndSettle();

    expect(find.text('演示模式 · 虚构数据'), findsOneWidget);
    expect(find.text('demo@example.test'), findsOneWidget);
    expect(find.text('演示节点 A'), findsOneWidget);
    expect(find.text('团队演示套餐'), findsOneWidget);
    expect(find.text('注册此设备'), findsNothing);
    expect(find.text('退出所有设备'), findsNothing);
    expect(find.text('连接功能未启用'), findsOneWidget);

    final connectButton = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, '连接功能未启用'),
    );
    expect(connectButton.onPressed, isNull);
  });
}
