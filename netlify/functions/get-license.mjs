import { getStore } from "@netlify/blobs";

export default async (req) => {
  const txnId = new URL(req.url).searchParams.get("txn_id");

  if (!txnId || !txnId.startsWith("txn_")) {
    return Response.json({ error: "invalid txn_id" }, { status: 400 });
  }

  const store = getStore({ name: "licenses", consistency: "strong" });
  const data = await store.get(txnId);

  if (!data) {
    return Response.json({ ready: false });
  }

  return Response.json({ ready: true, key: data });
};

export const config = { path: "/api/get-license" };
