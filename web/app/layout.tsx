import type { Metadata } from "next";
import "./globals.css";
import { AppShell } from "@/components/app-shell";
import { GuidedTour } from "@/components/guided-tour";

export const metadata: Metadata = {
  title: "Local Security Agent",
  description: "AI-assisted application security analysis — running locally.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
        <GuidedTour />
      </body>
    </html>
  );
}
