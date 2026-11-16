/// Synthetic, in-memory data for the client preview mode.
class ClientDemoData {
  const ClientDemoData({
    required this.user,
    required this.subscription,
    required this.subscriptionHistory,
    required this.devices,
  });

  final Map<String, dynamic> user;
  final Map<String, dynamic> subscription;
  final List<Map<String, dynamic>> subscriptionHistory;
  final List<Map<String, dynamic>> devices;
}

ClientDemoData buildDemoData(DateTime now) {
  final startsAt = now.subtract(const Duration(days: 3)).toUtc();
  final endsAt = now.add(const Duration(days: 27)).toUtc();
  final previousStartsAt = now.subtract(const Duration(days: 70)).toUtc();
  final previousEndsAt = now.subtract(const Duration(days: 40)).toUtc();
  final startsAtText = startsAt.toIso8601String();
  final endsAtText = endsAt.toIso8601String();
  final previousStartsAtText = previousStartsAt.toIso8601String();
  final previousEndsAtText = previousEndsAt.toIso8601String();

  return ClientDemoData(
    user: const {
      'id': 1001,
      'email': 'demo@example.test',
      'status': 'active',
    },
    subscription: {
      'id': 501,
      'plan_id': 2,
      'plan_name': '团队演示套餐',
      'device_limit': 3,
      'concurrent_limit': 2,
      'data_limit_bytes': 0,
      'speed_limit_mbps': 0,
      'starts_at': startsAtText,
      'ends_at': endsAtText,
    },
    subscriptionHistory: [
      {
        'id': 501,
        'plan_id': 2,
        'plan_name': '团队演示套餐',
        'status': 'active',
        'starts_at': startsAtText,
        'ends_at': endsAtText,
      },
      {
        'id': 438,
        'plan_id': 1,
        'plan_name': '基础演示套餐',
        'status': 'expired',
        'starts_at': previousStartsAtText,
        'ends_at': previousEndsAtText,
      },
    ],
    devices: [
      {
        'id': 301,
        'name': '演示工作电脑',
        'platform': 'windows',
        'public_key': '',
        'created_at': startsAtText,
        'last_seen_at': null,
        'revoked_at': null,
      },
      {
        'id': 302,
        'name': '演示手机',
        'platform': 'android',
        'public_key': '',
        'created_at': startsAtText,
        'last_seen_at': null,
        'revoked_at': null,
      },
      {
        'id': 299,
        'name': '旧演示设备',
        'platform': 'macos',
        'public_key': '',
        'created_at': previousStartsAtText,
        'last_seen_at': null,
        'revoked_at': previousEndsAtText,
      },
    ],
  );
}
