import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  NativeModules,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  Share,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from 'react-native';

type Status = 'pass' | 'fail' | 'warn' | 'info';

type Item = {
  id: string;
  category: string;
  title: string;
  status: Status;
  detail: string;
  blocking: boolean;
};

type CheckResult = {
  bootloader: 'LOCKED' | 'UNLOCKED' | 'UNKNOWN';
  overall: 'LIKELY_PASS' | 'REVIEW' | 'LIKELY_BLOCKED';
  pass: number;
  fail: number;
  warn: number;
  info: number;
  blockingFail: number;
  checks: Item[];
};

const { BootloaderCheck } = NativeModules as {
  BootloaderCheck?: { check: () => Promise<CheckResult> };
};

const CATEGORIES: { key: string; label: string }[] = [
  { key: 'INTEGRITY', label: 'Device integrity' },
  { key: 'ROOT', label: 'Root' },
  { key: 'TAMPER', label: 'Tampering and hooking' },
  { key: 'SETTINGS', label: 'Device settings' },
  { key: 'SCREEN', label: 'Screen safety' },
  { key: 'BINDING', label: 'SIM and device binding' },
  { key: 'NETWORK', label: 'Network' },
  { key: 'SERVER', label: 'Server-side only (Play Integrity)' },
  { key: 'DEVICE', label: 'Device info' },
];

const STATUS_COLOR: Record<Status, string> = {
  pass: '#16a34a',
  fail: '#dc2626',
  warn: '#d97706',
  info: '#64748b',
};

const STATUS_LABEL: Record<Status, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  warn: 'WARN',
  info: 'INFO',
};

const OVERALL: Record<
  CheckResult['overall'],
  { color: string; title: string; text: string }
> = {
  LIKELY_PASS: {
    color: '#16a34a',
    title: 'LIKELY PASS',
    text: 'No blocking problems found on-device.',
  },
  REVIEW: {
    color: '#d97706',
    title: 'REVIEW',
    text: 'No hard blockers, but some warnings could still trigger a bank.',
  },
  LIKELY_BLOCKED: {
    color: '#dc2626',
    title: 'LIKELY BLOCKED',
    text: 'At least one check that banks commonly block on has failed.',
  },
};

type Filter = 'all' | 'problems';

export default function BootloaderCheckScreen() {
  const [result, setResult] = useState<CheckResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [open, setOpen] = useState<Record<string, boolean>>({});

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

  const grouped = useMemo(() => {
    if (!result) {
      return [];
    }
    return CATEGORIES.map(c => ({
      ...c,
      items: result.checks.filter(
        i =>
          i.category === c.key &&
          (filter === 'all' || i.status === 'fail' || i.status === 'warn'),
      ),
    })).filter(g => g.items.length > 0);
  }, [result, filter]);

  const shareReport = useCallback(() => {
    if (!result) {
      return;
    }
    const lines = result.checks.map(
      i =>
        `[${STATUS_LABEL[i.status]}] ${i.category} - ${i.title}: ${i.detail}`,
    );
    Share.share({
      message: `Bootloader: ${result.bootloader}\nOverall: ${result.overall}\n\n${lines.join('\n')}`,
    });
  }, [result]);

  const o = result ? OVERALL[result.overall] : null;

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Device Integrity Check</Text>

        {loading && <ActivityIndicator size="large" style={styles.loader} />}
        {error && <Text style={styles.error}>{error}</Text>}

        {result && o && !loading && (
          <>
            <View style={[styles.badge, { backgroundColor: o.color }]}>
              <Text style={styles.badgeText}>{o.title}</Text>
              <Text style={styles.badgeSub}>{o.text}</Text>
              <Text style={styles.badgeSub}>
                Bootloader: {result.bootloader}
              </Text>
            </View>

            <View style={styles.counts}>
              {(['pass', 'warn', 'fail', 'info'] as Status[]).map(s => (
                <View key={s} style={styles.count}>
                  <Text style={[styles.countNum, { color: STATUS_COLOR[s] }]}>
                    {result[s]}
                  </Text>
                  <Text style={styles.countLabel}>{STATUS_LABEL[s]}</Text>
                </View>
              ))}
            </View>

            <View style={styles.filters}>
              {(['all', 'problems'] as Filter[]).map(f => (
                <Pressable
                  key={f}
                  onPress={() => setFilter(f)}
                  style={[styles.chip, filter === f && styles.chipOn]}>
                  <Text
                    style={[styles.chipText, filter === f && styles.chipTextOn]}>
                    {f === 'all' ? 'All checks' : 'Problems only'}
                  </Text>
                </Pressable>
              ))}
            </View>

            {grouped.map(g => (
              <View key={g.key}>
                <Text style={styles.section}>{g.label}</Text>
                <View style={styles.card}>
                  {g.items.map((i, idx) => {
                    const expanded = !!open[i.id];
                    return (
                      <Pressable
                        key={i.id}
                        onPress={() =>
                          setOpen(p => ({ ...p, [i.id]: !p[i.id] }))
                        }
                        style={[styles.item, idx > 0 && styles.itemBorder]}>
                        <View style={styles.itemHead}>
                          <View
                            style={[
                              styles.pill,
                              { backgroundColor: STATUS_COLOR[i.status] },
                            ]}>
                            <Text style={styles.pillText}>
                              {STATUS_LABEL[i.status]}
                            </Text>
                          </View>
                          <Text style={styles.itemTitle}>
                            {i.title}
                            {i.blocking ? '  *' : ''}
                          </Text>
                        </View>
                        <Text
                          style={styles.itemDetail}
                          numberOfLines={expanded ? undefined : 2}>
                          {i.detail}
                        </Text>
                      </Pressable>
                    );
                  })}
                </View>
              </View>
            ))}

            <Text style={styles.note}>
              * Banks commonly refuse to run when this check fails. On-device
              checks are telemetry only: the verdict a bank trusts is the Play
              Integrity result decoded on its server. Tap a row to expand it.
            </Text>

            <Pressable style={styles.secondary} onPress={shareReport}>
              <Text style={styles.secondaryText}>Share full report</Text>
            </Pressable>
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
  safe: {
    flex: 1,
    backgroundColor: '#f8fafc',
    paddingTop: Platform.OS === 'android' ? StatusBar.currentHeight ?? 0 : 0,
  },
  content: { padding: 20, paddingBottom: 48 },
  title: { fontSize: 24, fontWeight: '700', color: '#0f172a', marginBottom: 16 },
  loader: { marginVertical: 32 },
  error: { color: '#dc2626', marginBottom: 16 },
  badge: { borderRadius: 16, padding: 20, alignItems: 'center' },
  badgeText: { color: '#fff', fontSize: 30, fontWeight: '800' },
  badgeSub: { color: '#fff', marginTop: 6, textAlign: 'center' },
  counts: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginTop: 16,
    backgroundColor: '#fff',
    borderRadius: 12,
    paddingVertical: 12,
  },
  count: { alignItems: 'center' },
  countNum: { fontSize: 22, fontWeight: '800' },
  countLabel: { fontSize: 11, color: '#64748b', fontWeight: '600' },
  filters: { flexDirection: 'row', gap: 8, marginTop: 16 },
  chip: {
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 20,
    backgroundColor: '#e2e8f0',
  },
  chipOn: { backgroundColor: '#2563eb' },
  chipText: { color: '#334155', fontWeight: '600' },
  chipTextOn: { color: '#fff' },
  section: {
    marginTop: 20,
    marginBottom: 8,
    fontSize: 13,
    fontWeight: '700',
    color: '#334155',
    textTransform: 'uppercase',
  },
  card: { backgroundColor: '#fff', borderRadius: 12, paddingHorizontal: 12 },
  item: { paddingVertical: 10 },
  itemBorder: { borderTopWidth: StyleSheet.hairlineWidth, borderColor: '#e2e8f0' },
  itemHead: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  pill: { borderRadius: 6, paddingHorizontal: 6, paddingVertical: 2 },
  pillText: { color: '#fff', fontSize: 10, fontWeight: '800' },
  itemTitle: { flex: 1, color: '#0f172a', fontWeight: '600' },
  itemDetail: { marginTop: 4, color: '#64748b', fontSize: 12, lineHeight: 17 },
  note: { marginTop: 20, color: '#64748b', fontSize: 12, lineHeight: 18 },
  secondary: {
    marginTop: 16,
    borderRadius: 12,
    paddingVertical: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#2563eb',
  },
  secondaryText: { color: '#2563eb', fontWeight: '700' },
  button: {
    marginTop: 12,
    backgroundColor: '#2563eb',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonDisabled: { opacity: 0.5 },
  buttonText: { color: '#fff', fontWeight: '700', fontSize: 16 },
});