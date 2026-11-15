import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const VpnClientApp());
}

class VpnClientApp extends StatelessWidget {
  const VpnClientApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VPN Client',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const ClientHome(),
    );
  }
}

class ClientHome extends StatefulWidget {
  const ClientHome({super.key});

  @override
  State<ClientHome> createState() => _ClientHomeState();
}

class _ClientHomeState extends State<ClientHome> {
  static const _secureStorage = FlutterSecureStorage();
  static const _tokenStorageKey = 'api_access_token_v1';

  final _baseUrlController = TextEditingController(
    text: 'http://localhost:8080',
  );
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _inviteCodeController = TextEditingController();

  String? _token;
  Map<String, dynamic>? _user;
  Map<String, dynamic>? _subscription;
  List<dynamic> _devices = [];
  String? _message;
  String? _subscriptionMessage;
  String? _devicesMessage;
  bool _busy = false;
  bool _isRegistering = false;
  bool _sessionReady = false;

  @override
  void initState() {
    super.initState();
    _restoreSession();
  }

  Future<void> _restoreSession() async {
    try {
      final savedToken = await _secureStorage.read(key: _tokenStorageKey);
      if (savedToken != null && savedToken.isNotEmpty) {
        if (!mounted) return;
        setState(() => _token = savedToken);
        await _loadAccount();
      }
    } catch (_) {
      if (mounted) {
        setState(() => _message = '无法读取已保存的登录状态，请重新登录');
      }
    } finally {
      if (mounted) setState(() => _sessionReady = true);
    }
  }

  Future<void> _saveSessionToken(String token) async {
    await _secureStorage.write(key: _tokenStorageKey, value: token);
    if (mounted) setState(() => _token = token);
  }

  String get _baseUrl => _baseUrlController.text.trim().replaceAll(
        RegExp(r'/+$'),
        '',
      );

  String _currentPlatform() {
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return 'android';
      case TargetPlatform.iOS:
        return 'ios';
      case TargetPlatform.windows:
        return 'windows';
      case TargetPlatform.macOS:
        return 'macos';
      default:
        throw UnsupportedError('当前平台暂不支持设备注册');
    }
  }

  Future<dynamic> _request(
    String path, {
    String method = 'GET',
    Map<String, dynamic>? body,
  }) async {
    final uri = Uri.parse('$_baseUrl$path');
    final headers = <String, String>{
      'Accept': 'application/json',
      if (body != null) 'Content-Type': 'application/json',
      if (_token != null) 'Authorization': 'Bearer $_token',
    };

    late http.Response response;
    switch (method) {
      case 'POST':
        response = await http.post(
          uri,
          headers: headers,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'PATCH':
        response = await http.patch(
          uri,
          headers: headers,
          body: body == null ? null : jsonEncode(body),
        );
        break;
      case 'DELETE':
        response = await http.delete(uri, headers: headers);
        break;
      default:
        response = await http.get(uri, headers: headers);
    }

    if (response.statusCode == 204 || response.body.isEmpty) return null;

    dynamic decoded;
    try {
      decoded = jsonDecode(response.body);
    } catch (_) {
      throw Exception('服务器返回了无法识别的数据');
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final error = decoded is Map ? decoded['error'] : null;
      if (_token != null &&
          response.statusCode == 401 &&
          (error == 'unauthorized' ||
              error == 'invalid_token' ||
              error == 'user_not_found')) {
        await _logout(message: error.toString());
      }
      throw Exception(error?.toString() ?? '请求失败 (${response.statusCode})');
    }
    return decoded;
  }

  Future<void> _login() async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      final result = await _request(
        '/v1/auth/login',
        method: 'POST',
        body: {
          'email': _emailController.text.trim(),
          'password': _passwordController.text,
        },
      );
      if (result is! Map<String, dynamic>) {
        throw Exception('登录响应格式无效');
      }
      final token = result['token'];
      if (token is! String || token.isEmpty) {
        throw Exception('登录响应中没有令牌');
      }
      if (!mounted) return;
      await _saveSessionToken(token);
      await _loadAccount();
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _register() async {
    final email = _emailController.text.trim();
    final password = _passwordController.text;
    final inviteCode = _inviteCodeController.text.trim();

    if (email.isEmpty || password.isEmpty || inviteCode.isEmpty) {
      setState(() => _message = '请填写邮箱、密码和邀请口令');
      return;
    }

    final passwordBytes = utf8.encode(password).length;
    if (passwordBytes < 12 || passwordBytes > 72) {
      setState(() => _message = '密码长度必须为 12–72 字节');
      return;
    }

    setState(() {
      _busy = true;
      _message = null;
    });
    var registeredOnServer = false;
    try {
      final result = await _request(
        '/v1/auth/register',
        method: 'POST',
        body: {
          'email': email,
          'password': password,
          'invite_code': inviteCode,
        },
      );
      if (result is! Map<String, dynamic>) {
        throw Exception('注册响应格式无效');
      }
      final token = result['token'];
      if (token is! String || token.isEmpty) {
        throw Exception('注册响应中没有令牌');
      }
      registeredOnServer = true;
      _inviteCodeController.clear();
      if (!mounted) return;
      await _saveSessionToken(token);
      await _loadAccount();
      if (mounted) setState(() => _message = '注册成功');
    } catch (error) {
      if (mounted) {
        setState(() => _message = registeredOnServer
            ? '账号已注册，但无法保存登录状态；请使用刚注册的账号登录。${_errorText(error)}'
            : _errorText(error));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _loadAccount() async {
    try {
      final me = await _request('/v1/me');
      if (me is! Map<String, dynamic>) throw Exception('账号信息格式无效');

      Map<String, dynamic>? subscription;
      String? subscriptionMessage;
      try {
        final result = await _request('/v1/me/subscription');
        if (result is Map<String, dynamic>) subscription = result;
      } catch (error) {
        if (_errorText(error) != 'no_active_subscription') {
          subscriptionMessage = _errorText(error);
        }
      }

      List<dynamic> devices = [];
      String? devicesMessage;
      try {
        final result = await _request('/v1/devices');
        if (result is List) {
          devices = result;
          for (final item in devices) {
            if (item is Map && item['revoked_at'] != null) {
              final publicKey = item['public_key'];
              if (publicKey is String && publicKey.isNotEmpty) {
                await _secureStorage.delete(key: 'wg_private_$publicKey');
                await _secureStorage.delete(key: 'wg_pending_$publicKey');
              }
            }
          }
        }
      } catch (error) {
        devicesMessage = _errorText(error);
      }

      if (!mounted) return;
      setState(() {
        _user = me;
        _subscription = subscription;
        _devices = devices;
        _subscriptionMessage = subscriptionMessage;
        _devicesMessage = devicesMessage;
        _message = null;
      });
    } catch (error) {
      if (!mounted) return;
      final text = _errorText(error);
      if (text == 'invalid_token' || text == 'unauthorized') {
        await _logout(message: text);
      } else {
        setState(() => _message = text);
      }
    }
  }

  Future<void> _revokeDevice(dynamic device) async {
    if (device is! Map) return;
    final id = device['id'];
    if (id == null) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('撤销设备'),
        content: Text('确定撤销设备“${device['name'] ?? ''}”吗？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('撤销'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await _request('/v1/devices/$id', method: 'DELETE');
      String? cleanupError;
      final publicKey = device['public_key'];
      if (publicKey is String && publicKey.isNotEmpty) {
        try {
          await _secureStorage.delete(key: 'wg_private_$publicKey');
          await _secureStorage.delete(key: 'wg_pending_$publicKey');
        } catch (error) {
          cleanupError = _errorText(error);
        }
      }
      await _loadAccount();
      if (mounted && _token != null) {
        setState(() => _message = cleanupError == null
            ? '设备已撤销'
            : '设备已撤销，但本地密钥清理失败：$cleanupError');
      }
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _renameDevice(dynamic value) async {
    if (value is! Map || value['id'] == null) return;

    final controller = TextEditingController(
      text: value['name']?.toString() ?? '',
    );
    final name = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('重命名设备'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength: 64,
          decoration: const InputDecoration(labelText: '设备名称'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () =>
                Navigator.pop(dialogContext, controller.text.trim()),
            child: const Text('保存'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null || !mounted) return;

    if (name.isEmpty || utf8.encode(name).length > 64) {
      setState(() => _message = '设备名称必须为 1–64 字节');
      return;
    }

    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await _request(
        '/v1/devices/${value['id']}',
        method: 'PATCH',
        body: {'name': name},
      );
      await _loadAccount();
      if (mounted) setState(() => _message = '设备名称已更新');
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _registerDevice() async {
    final nameController = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('注册此设备'),
        content: TextField(
          controller: nameController,
          autofocus: true,
          maxLength: 64,
          decoration: const InputDecoration(labelText: '设备名称'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () =>
                Navigator.pop(context, nameController.text.trim()),
            child: const Text('继续'),
          ),
        ],
      ),
    );
    nameController.dispose();
    if (name == null || name.isEmpty || !mounted) return;

    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      final platform = _currentPlatform();
      final algorithm = X25519();
      final keyPair = await algorithm.newKeyPair();
      final keyPairData = await keyPair.extract();
      final publicKey = await keyPair.extractPublicKey();
      final publicKeyBase64 = base64Encode(publicKey.bytes);
      final privateKeyBase64 = base64Encode(keyPairData.privateKey);

      // The private key is written to system secure storage and never sent to the API.
      final storageKey = 'wg_private_$publicKeyBase64';
      final pendingKey = 'wg_pending_$publicKeyBase64';
      await _secureStorage.write(key: storageKey, value: privateKeyBase64);
      await _secureStorage.write(
        key: pendingKey,
        value: jsonEncode({'name': name, 'platform': platform}),
      );

      final result = await _request(
        '/v1/devices',
        method: 'POST',
        body: {
          'name': name,
          'platform': platform,
          'public_key': publicKeyBase64,
        },
      );
      if (result is! Map || result['id'] == null) {
        throw Exception('设备已提交，但服务器没有返回设备 ID');
      }

      await _secureStorage.delete(key: pendingKey);
      await _loadAccount();
      if (mounted && _message == null) {
        setState(() => _message = '设备注册成功');
      }
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _retryPendingRegistrations() async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      final all = await _secureStorage.readAll();
      final pendingEntries = all.entries
          .where((entry) => entry.key.startsWith('wg_pending_'))
          .toList();

      if (pendingEntries.isEmpty) {
        if (mounted) setState(() => _message = '没有待重试的设备注册');
        return;
      }

      for (final entry in pendingEntries) {
        final publicKey = entry.key.substring('wg_pending_'.length);
        final decodedMetadata = jsonDecode(entry.value);
        if (decodedMetadata is! Map) {
          throw Exception('待处理设备信息格式无效');
        }
        final name = decodedMetadata['name'];
        final platform = decodedMetadata['platform'];
        if (name is! String || platform is! String) {
          throw Exception('待处理设备信息缺少名称或平台');
        }

        // Check the server first in case the original request succeeded but its response was lost.
        final listResult = await _request('/v1/devices');
        List<dynamic>? serverDevices;
        if (listResult is List) {
          serverDevices = listResult;
        } else if (listResult is Map && listResult['data'] is List) {
          serverDevices = listResult['data'] as List<dynamic>;
        }
        if (serverDevices == null) {
          throw Exception('服务器设备列表格式无效');
        }

        Map? existingDevice;
        for (final item in serverDevices) {
          if (item is Map && item['public_key'] == publicKey) {
            existingDevice = item;
            break;
          }
        }

        if (existingDevice is Map && existingDevice['revoked_at'] != null) {
          await _secureStorage.delete(key: 'wg_private_$publicKey');
        } else {
          final privateKey = await _secureStorage.read(key: 'wg_private_$publicKey');
          if (privateKey == null || privateKey.isEmpty) {
            throw Exception('待重试设备的本地私钥不存在，无法安全重试');
          }
          if (existingDevice == null) {
            final result = await _request(
              '/v1/devices',
              method: 'POST',
              body: {
                'name': name,
                'platform': platform,
                'public_key': publicKey,
              },
            );
            if (result is! Map || result['id'] == null) {
              throw Exception('服务器没有返回设备 ID');
            }
          }
        }

        await _secureStorage.delete(key: entry.key);
      }

      await _loadAccount();
      if (mounted && _token != null && _message == null) {
        setState(() => _message = '待处理的设备注册已完成');
      }
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _changePassword() async {
    final currentController = TextEditingController();
    final newController = TextEditingController();
    final confirmController = TextEditingController();

    final values = await showDialog<List<String>>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('修改密码'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: currentController,
                obscureText: true,
                decoration: const InputDecoration(labelText: '当前密码'),
              ),
              TextField(
                controller: newController,
                obscureText: true,
                decoration: const InputDecoration(labelText: '新密码'),
              ),
              TextField(
                controller: confirmController,
                obscureText: true,
                decoration: const InputDecoration(labelText: '确认新密码'),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, [
              currentController.text,
              newController.text,
              confirmController.text,
            ]),
            child: const Text('确认修改'),
          ),
        ],
      ),
    );

    currentController.dispose();
    newController.dispose();
    confirmController.dispose();
    if (values == null || !mounted) return;

    final currentPassword = values[0];
    final newPassword = values[1];
    if (newPassword != values[2]) {
      setState(() => _message = '两次输入的新密码不一致');
      return;
    }

    final byteLength = utf8.encode(newPassword).length;
    if (byteLength < 12 || byteLength > 72) {
      setState(() => _message = '新密码长度必须为 12–72 字节');
      return;
    }

    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await _request(
        '/v1/me/password',
        method: 'POST',
        body: {
          'current_password': currentPassword,
          'new_password': newPassword,
        },
      );
      if (mounted) await _logout(message: '密码已修改，请使用新密码重新登录');
    } catch (error) {
      if (mounted) setState(() => _message = _errorText(error));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _errorText(Object error) =>
      error.toString().replaceFirst('Exception: ', '');

  Future<void> _logout({String? message}) async {
    try {
      await _secureStorage.delete(key: _tokenStorageKey);
    } catch (_) {
      // Clear the in-memory session even if the platform secure store fails.
    }
    if (!mounted) return;
    setState(() {
      _token = null;
      _user = null;
      _subscription = null;
      _devices = [];
      _subscriptionMessage = null;
      _devicesMessage = null;
      _message = message;
      _passwordController.clear();
      _inviteCodeController.clear();
      _isRegistering = false;
    });
  }

  @override
  void dispose() {
    _baseUrlController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _inviteCodeController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!_sessionReady) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('VPN 客户端'),
        actions: [
          if (_token != null)
            IconButton(
              tooltip: '刷新',
              onPressed: _busy ? null : _loadAccount,
              icon: const Icon(Icons.refresh),
            ),
          if (_token != null)
            IconButton(
              tooltip: '退出登录',
              onPressed: () => _logout(),
              icon: const Icon(Icons.logout),
            ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: ListView(
            padding: const EdgeInsets.all(20),
            children: [
              if (_message != null)
                Card(
                  color: Theme.of(context).colorScheme.errorContainer,
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Text(_message!),
                  ),
                ),
              if (_token == null) _buildLoginForm() else _buildAccount(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildLoginForm() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              _isRegistering ? '使用邀请口令注册' : '登录',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _baseUrlController,
              decoration: const InputDecoration(
                labelText: 'API 地址',
                hintText: '例如 http://localhost:8080',
              ),
              keyboardType: TextInputType.url,
            ),
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text(
                'Android 模拟器通常使用 http://10.0.2.2:8080；桌面开发可使用 http://localhost:8080。',
                style: TextStyle(color: Colors.grey),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _emailController,
              decoration: const InputDecoration(labelText: '邮箱'),
              keyboardType: TextInputType.emailAddress,
              autofillHints: const [AutofillHints.username],
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: '密码'),
              obscureText: true,
              autofillHints: const [AutofillHints.password],
              onSubmitted: (_) => _busy
                  ? null
                  : (_isRegistering ? _register() : _login()),
            ),
            if (_isRegistering) ...[
              const SizedBox(height: 8),
              TextField(
                controller: _inviteCodeController,
                decoration: const InputDecoration(labelText: '邀请口令'),
                obscureText: true,
                autofillHints: const [AutofillHints.oneTimeCode],
              ),
            ],
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _busy
                  ? null
                  : (_isRegistering ? _register : _login),
              child: Text(
                _busy ? '请稍候…' : (_isRegistering ? '注册并登录' : '登录'),
              ),
            ),
            TextButton(
              onPressed: _busy
                  ? null
                  : () {
                      setState(() {
                        _isRegistering = !_isRegistering;
                        _message = null;
                      });
                    },
              child: Text(
                _isRegistering ? '已有账号？返回登录' : '没有账号？使用邀请口令注册',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAccount() {
    final email = _user?['email']?.toString() ?? '加载中…';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.account_circle),
            title: Text(email),
            subtitle: Text('用户 ID：${_user?['id'] ?? '—'}'),
          ),
        ),
        Align(
          alignment: Alignment.centerLeft,
          child: OutlinedButton.icon(
            onPressed: _busy ? null : _changePassword,
            icon: const Icon(Icons.lock_reset),
            label: const Text('修改密码'),
          ),
        ),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: _subscriptionCard(),
          ),
        ),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('我的设备', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 8),
                FilledButton.icon(
                  onPressed: _busy ? null : _registerDevice,
                  icon: const Icon(Icons.add),
                  label: const Text('注册此设备'),
                ),
                OutlinedButton.icon(
                  onPressed: _busy ? null : _retryPendingRegistrations,
                  icon: const Icon(Icons.sync),
                  label: const Text('重试待处理注册'),
                ),
                const SizedBox(height: 8),
                if (_devicesMessage != null)
                  Text(_devicesMessage!,
                      style: TextStyle(color: Theme.of(context).colorScheme.error))
                else if (_devices.isEmpty)
                  const Text('暂无设备。')
                else
                  ..._devices.map(_deviceTile),
                const SizedBox(height: 8),
                const Text(
                  '此版本尚未生成设备密钥或建立 VPN 连接。',
                  style: TextStyle(color: Colors.grey),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _subscriptionCard() {
    final subscription = _subscription;
    if (_subscriptionMessage != null) {
      return Text('订阅信息加载失败：$_subscriptionMessage');
    }
    if (subscription == null) return const Text('当前没有有效订阅。');
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('当前套餐：${subscription['plan_name'] ?? '—'}',
            style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 6),
        Text('设备数上限：${subscription['device_limit'] ?? '—'}'),
        Text('并发数上限：${subscription['concurrent_limit'] ?? '—'}'),
        Text('流量上限：${subscription['data_limit_bytes'] ?? 0} 字节（0 表示不限）'),
        Text('速度上限：${subscription['speed_limit_mbps'] ?? 0} Mbps（0 表示不限）'),
        Text('到期时间：${subscription['ends_at'] ?? '—'}'),
      ],
    );
  }

  Widget _deviceTile(dynamic value) {
    if (value is! Map) return const SizedBox.shrink();
    final revoked = value['revoked_at'] != null;
    final name = value['name']?.toString() ?? '未命名设备';
    final platform = value['platform']?.toString() ?? '未知平台';
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(revoked ? Icons.devices : Icons.phone_android),
      title: Text(name),
      subtitle: Text('$platform · ${revoked ? '已撤销' : '有效'}'),
      trailing: revoked
          ? null
          : Wrap(
              spacing: 4,
              children: [
                IconButton(
                  tooltip: '重命名',
                  onPressed: _busy ? null : () => _renameDevice(value),
                  icon: const Icon(Icons.edit_outlined),
                ),
                IconButton(
                  tooltip: '撤销设备',
                  onPressed: _busy ? null : () => _revokeDevice(value),
                  icon: const Icon(Icons.delete_outline),
                ),
              ],
            ),
    );
  }
}
