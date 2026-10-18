import React, { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  NativeModules,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';

type Verdict = 'LOCKED' | 'UNLOCKED' | 'UNKNOWN';

type CheckResult = {
  verdict: Verdict;
  source: 'attestation' | 'props' | 'none';
  props: Record<string, string | null>;
  attestation: {
    deviceLocked: boolean | null;
    verifiedBootState: string | null;
    securityLevel: string | null;
    error: string | null;
  };
};

const { BootloaderCheck } = NativeModules as {
  BootloaderCheck?: { check: () => Promise<CheckResult> };
};

const COLORS: Record<Verdict, string> = {
  LOCKED: '#16a34a',
  UNLOCKED: '#dc2626',
  UNKNOWN: '#d97706',
};

const MESSAGES: Record<Verdict, string> = {
  LOCKED: 'Bootloader is locked. Banking apps should pass the device check.',
  UNLOCKED:
    'Bootloader is unlocked. Banking apps will likely fail Play Integrity.',
  UNKNOWN: 'Could not determine the bootloader state.',
};

const Row = ({ label, value }: { label: string; value: string }) => (
  <View style={styles.row}>
    <Text style={styles.rowLabel}>{label}</Text>
    <Text style={styles.rowValue}>{value}</Text>
  </View>
);

export default function BootloaderCheckScreen() {
  const [result, setResult] = useState<CheckResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (Platform.OS !== 'android' || !BootloaderCheck) {
        throw new Error('Native module is only available on Android.');
      }
      setResult(await BootloaderCheck.check());
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    run();
  }, [run]);

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Bootloader Check</Text>

        {loading && <ActivityIndicator size="large" style={styles.loader} />}

        {error && <Text style={styles.error}>{error}</Text>}

        {result && !loading && (
          <>
            <View
              style={[
                styles.badge,
                { backgroundColor: COLORS[result.verdict] },
              ]}>
              <Text style={styles.badgeText}>{result.verdict}</Text>
              <Text style={styles.badgeSub}>{MESSAGES[result.verdict]}</Text>
            </View>

            <Text style={styles.source}>
              Verdict source: {result.source}
              {result.source === 'attestation' ? ' (hardware-backed)' : ''}
            </Text>

            <Text style={styles.section}>Key attestation</Text>
            <View style={styles.card}>
              <Row
                label="Device locked"
                value={String(result.attestation.deviceLocked ?? 'n/a')}
              />
              <Row
                label="Verified boot"
                value={result.attestation.verifiedBootState ?? 'n/a'}
              />
              <Row
                label="Security level"
                value={result.attestation.securityLevel ?? 'n/a'}
              />
              {result.attestation.error && (
                <Row label="Error" value={result.attestation.error} />
              )}
            </View>

            <Text style={styles.section}>System properties</Text>
            <View style={styles.card}>
              {Object.entries(result.props).map(([k, v]) => (
                <Row key={k} label={k.replace('ro.boot.', '')} value={v ?? 'n/a'} />
              ))}
            </View>

            <Text style={styles.note}>
              This is an on-device check and can be spoofed by root tools. For
              anything security-sensitive, verify the attestation chain or Play
              Integrity token on your server.
            </Text>
          </>
        )}

        <Pressable
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={run}
          disabled={loading}>
          <Text style={styles.buttonText}>Verify again</Text>
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#f8fafc' },
  content: { padding: 20 },
  title: { fontSize: 24, fontWeight: '700', color: '#0f172a', marginBottom: 16 },
  loader: { marginVertical: 32 },
  error: { color: '#dc2626', marginBottom: 16 },
  badge: { borderRadius: 16, padding: 20, alignItems: 'center' },
  badgeText: { color: '#fff', fontSize: 32, fontWeight: '800' },
  badgeSub: { color: '#fff', marginTop: 8, textAlign: 'center' },
  source: { marginTop: 10, color: '#475569', fontSize: 12 },
  section: {
    marginTop: 20,
    marginBottom: 8,
    fontSize: 14,
    fontWeight: '700',
    color: '#334155',
    textTransform: 'uppercase',
  },
  card: { backgroundColor: '#fff', borderRadius: 12, padding: 12 },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
  },
  rowLabel: { color: '#64748b', flex: 1 },
  rowValue: { color: '#0f172a', fontWeight: '600', flex: 1, textAlign: 'right' },
  note: { marginTop: 20, color: '#64748b', fontSize: 12, lineHeight: 18 },
  button: {
    marginTop: 24,
    backgroundColor: '#2563eb',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: '#fff', fontWeight: '700', fontSize: 16 },
});