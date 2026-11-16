import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_platform_client/main.dart';

void main() {
  group('parseApiBaseUrl', () {
    test('accepts remote HTTPS URLs', () {
      expect(parseApiBaseUrl('https://vpn.example.com').scheme, 'https');
    });

    test('allows HTTP for local development hosts', () {
      expect(parseApiBaseUrl('http://localhost:8080').host, 'localhost');
      expect(parseApiBaseUrl('http://127.0.0.1:8080').host, '127.0.0.1');
      expect(parseApiBaseUrl('http://10.0.2.2:8080').host, '10.0.2.2');
      expect(parseApiBaseUrl('http://[::1]:8080').host, '::1');
    });

    test('rejects remote plaintext HTTP', () {
      expect(
        () => parseApiBaseUrl('http://vpn.example.com'),
        throwsFormatException,
      );
    });

    test('rejects credentials, query parameters, and extra paths', () {
      expect(
        () => parseApiBaseUrl('https://user:pass@example.com'),
        throwsFormatException,
      );
      expect(
        () => parseApiBaseUrl('https://example.com?token=secret'),
        throwsFormatException,
      );
      expect(
        () => parseApiBaseUrl('https://example.com/api'),
        throwsFormatException,
      );
    });
  });
}
