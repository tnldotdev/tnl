"use client";

export default function Page() {
  return (
    <main>
      <h1>Next.js fixture</h1>
      <p>{`url:${process.env.NEXT_PUBLIC_TNL_URL}`}</p>
      <p>{`hostname:${process.env.NEXT_PUBLIC_TNL_HOSTNAME}`}</p>
      <p>{`tunnel-id:${process.env.NEXT_PUBLIC_TNL_TUNNEL_ID}`}</p>
    </main>
  );
}
