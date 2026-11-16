import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_platform_client/demo_data.dart';

void main() {
  test(
    'demo data is synthetic and covers account, subscription and devices',
    () {
      final data = buildDemoData(DateTime.utc(2030, 1, 1));

      expect(data.user['email'], 'demo@example.test');
      expect(data.user['status'], 'active');
      expect(data.subscription['plan_name'], '团队演示套餐');
      expect(data.subscriptionHistory.map((item) => item['status']), [
        'active',
        'expired',
      ]);
      expect(data.devices, hasLength(3));
      expect(
        data.devices.every((device) => device['public_key'] == ''),
        isTrue,
      );
      expect(
        data.devices.any((device) => device['revoked_at'] != null),
        isTrue,
      );
    },
  );
}
