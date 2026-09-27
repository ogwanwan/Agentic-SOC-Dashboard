import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SSOC Dashboard",
  description: "SSOC 보안 분석 결과와 파이프라인 운영 현황을 확인하는 대시보드",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ko">
      <body className="antialiased">{children}</body>
    </html>
  );
}
