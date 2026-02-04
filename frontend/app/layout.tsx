import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FirePan Dashboard",
  description: "AI-powered smart contract security platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
