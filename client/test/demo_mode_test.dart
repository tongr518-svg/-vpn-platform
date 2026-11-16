import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:vpn_platform_client/main.dart';

const _secureStorageChannel =
    MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

void main() {
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_secureStorageChannel, (call) async => null);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_secureStorageChannel, null);
  });

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
