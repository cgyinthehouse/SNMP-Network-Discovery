export type TopologyNode = {
  id: string;
  label: string;
  ip?: string;
  type?: string;
  model?: string;
  mac?: string;
};

export type TopologyEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  protocol?: string;
  platform?: string;
};

export type Topology = {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
};

export type DiscoveredDevice = Record<string, unknown>;

export type DiscoverPayload = {
  ip: string | null;
  version: number;
  community: string | null;
  user: string | null;
  auth_key: string | null;
  priv_key: string | null;
  auth_proto: string | null;
  priv_proto: string | null;
};
