'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  IconDeviceFloppy,
  IconRefresh,
  IconCheck,
  IconX,
  IconLoader2,
  IconSettings2,
  IconInfoCircle,
} from '@tabler/icons-react';
import { SettingsServiceCard } from '@/components/settings';
import { ServiceConfig, AllSettingsResponse, UpdateSettingsRequest } from '@/types/settings';

type PendingChanges = Map<string, string | number | boolean>;

export default function SettingsPage() {
  const [services, setServices] = useState<ServiceConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingChanges, setPendingChanges] = useState<PendingChanges>(new Map());
  const [saveStatus, setSaveStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [lastSaved, setLastSaved] = useState<string | null>(null);

  // Fetch all settings
  const fetchSettings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/settings', {
        cache: 'no-store',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch settings');
      }

      const data: AllSettingsResponse = await response.json();
      setServices(data.services);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  // Handle parameter changes
  const handleParameterChange = useCallback(
    (service: string, section: string, key: string, value: string | number | boolean) => {
      setPendingChanges((prev) => {
        const next = new Map(prev);
        const changeKey = `${service}.${section}.${key}`;
        next.set(changeKey, value);
        return next;
      });
      setSaveStatus('idle');
    },
    []
  );

  // Save all changes
  const saveChanges = async () => {
    if (pendingChanges.size === 0) return;

    setSaving(true);
    setSaveStatus('idle');

    try {
      // Group changes by service
      const changesByService = new Map<string, UpdateSettingsRequest['updates']>();

      for (const [key, value] of pendingChanges.entries()) {
        const [service, section, paramKey] = key.split('.');
        if (!changesByService.has(service)) {
          changesByService.set(service, []);
        }
        changesByService.get(service)!.push({ section, key: paramKey, value });
      }

      // Save each service
      const results = await Promise.all(
        Array.from(changesByService.entries()).map(async ([service, updates]) => {
          const response = await fetch(`/api/settings/${service}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ updates }),
          });

          if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || `Failed to save ${service} settings`);
          }

          return response.json();
        })
      );

      // Clear pending changes and refresh
      setPendingChanges(new Map());
      setSaveStatus('success');
      setLastSaved(new Date().toLocaleTimeString());

      // Refresh data after short delay
      setTimeout(() => {
        fetchSettings();
      }, 500);

      // Reset status after 3 seconds
      setTimeout(() => {
        setSaveStatus('idle');
      }, 3000);
    } catch (err) {
      setSaveStatus('error');
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  // Discard all changes
  const discardChanges = () => {
    setPendingChanges(new Map());
    setSaveStatus('idle');
  };

  // Render loading state
  if (loading && services.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <IconLoader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-muted-foreground">Loading settings...</p>
      </div>
    );
  }

  // Render error state
  if (error && services.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <div className="p-4 rounded-xl bg-destructive/10 text-destructive">
          <IconX className="h-8 w-8" />
        </div>
        <p className="text-foreground font-medium">Failed to load settings</p>
        <p className="text-sm text-muted-foreground">{error}</p>
        <button
          onClick={fetchSettings}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <IconRefresh className="h-4 w-4" />
          Retry
        </button>
      </div>
    );
  }

  const hasChanges = pendingChanges.size > 0;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <IconSettings2 className="h-7 w-7 text-primary" />
            Settings
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure security and ML settings for each honeypot service
          </p>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          {lastSaved && saveStatus === 'success' && (
            <span className="text-xs text-muted-foreground">
              Last saved: {lastSaved}
            </span>
          )}

          {hasChanges && (
            <button
              onClick={discardChanges}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border border-border hover:bg-muted transition-colors"
            >
              <IconX className="h-4 w-4" />
              Discard
            </button>
          )}

          <button
            onClick={saveChanges}
            disabled={!hasChanges || saving}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {saving ? (
              <>
                <IconLoader2 className="h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : saveStatus === 'success' ? (
              <>
                <IconCheck className="h-4 w-4" />
                Saved!
              </>
            ) : (
              <>
                <IconDeviceFloppy className="h-4 w-4" />
                Save Changes
                {hasChanges && (
                  <span className="ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-primary-foreground/20">
                    {pendingChanges.size}
                  </span>
                )}
              </>
            )}
          </button>
        </div>
      </div>

      {/* Info Banner */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/10 border border-blue-500/20"
      >
        <IconInfoCircle className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-blue-500 dark:text-blue-400">
            Configuration Changes
          </p>
          <p className="text-muted-foreground mt-1">
            Changes are saved to <code className="px-1 py-0.5 rounded bg-muted text-xs">config.ini</code> files.
            A backup is created automatically before each save. Some changes may require a service restart to take effect.
          </p>
        </div>
      </motion.div>

      {/* Error Alert */}
      {error && services.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-3 p-4 rounded-xl bg-destructive/10 border border-destructive/20"
        >
          <IconX className="h-5 w-5 text-destructive shrink-0" />
          <p className="text-sm text-destructive">{error}</p>
          <button
            onClick={() => setError(null)}
            className="ml-auto p-1.5 rounded-lg hover:bg-destructive/10 transition-colors"
          >
            <IconX className="h-4 w-4 text-destructive" />
          </button>
        </motion.div>
      )}

      {/* Service Cards Grid */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-2 xl:grid-cols-3">
        {services.map((service) => (
          <SettingsServiceCard
            key={service.service}
            config={service}
            onParameterChange={(section, key, value) =>
              handleParameterChange(service.service, section, key, value)
            }
            pendingChanges={pendingChanges}
            disabled={saving}
          />
        ))}
      </div>

      {/* Empty State */}
      {services.length === 0 && !loading && (
        <div className="flex flex-col items-center justify-center py-16 gap-4">
          <div className="p-4 rounded-xl bg-muted">
            <IconSettings2 className="h-8 w-8 text-muted-foreground" />
          </div>
          <p className="text-muted-foreground">No service configurations found</p>
          <button
            onClick={fetchSettings}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <IconRefresh className="h-4 w-4" />
            Refresh
          </button>
        </div>
      )}
    </div>
  );
}