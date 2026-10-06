import type { Metadata } from "next";
import "./globals.css";
import { AppShell } from "@/components/app-shell";
import { DemoExperience } from "@/components/demo/demo-experience";

export const metadata: Metadata = {
  title: "Local Security Agent",
  description: "AI-assisted application security analysis — running locally.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
        <DemoExperience />
      </body>
    </html>
  );
}
