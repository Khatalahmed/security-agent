"use client";
import { api } from "@/lib/api";
import { useAsync } from "@/lib/use-async";
import { FindingsTable } from "@/components/findings-table";
import { Loading, ErrorState, Empty, PageTitle } from "@/components/states";

export default function FindingsPage() {
  const { data, loading, error } = useAsync(() => api.findings(), []);
  return (
    <div>
      <PageTitle title="Findings" subtitle="All candidate and reviewed findings across scans." />
      {loading ? <Loading /> : error ? <ErrorState message={error} />
        : !data || data.length === 0
          ? <Empty title="No findings" hint="No vulnerabilities were identified by the configured analysis. Run a scan with taint + validation enabled." />
          : <FindingsTable findings={data} />}
    </div>
  );
}
