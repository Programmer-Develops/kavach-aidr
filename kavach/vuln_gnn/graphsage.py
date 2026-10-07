"""
graphsage.py — Trainable VulnGNN (GraphSAGE) implemented in pure PyTorch.

Implements Eq. (i) of the paper:
    h_v^(k) = sigma( W^(k) . [ h_v^(k-1) || MEAN_{u in N(v)} h_u^(k-1) ] )
with two SAGE layers, global mean pooling and an MLP head with a sigmoid
output. No torch_geometric dependency: neighbourhood aggregation uses
index_add_ over the edge list.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

from kavach.vuln_gnn.cpg import FEATURE_DIM


class SAGELayer(nn.Module):
    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.lin = nn.Linear(2 * in_dim, out_dim)

    def forward(self, h: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        n = h.size(0)
        src, dst = edge_index
        agg = torch.zeros_like(h)
        agg.index_add_(0, dst, h[src])
        deg = torch.zeros(n, device=h.device)
        deg.index_add_(0, dst, torch.ones(dst.size(0), device=h.device))
        agg = agg / deg.clamp(min=1).unsqueeze(1)
        return F.relu(self.lin(torch.cat([h, agg], dim=1)))


class VulnGraphSAGE(nn.Module):
    def __init__(self, in_dim: int = FEATURE_DIM, hidden: int = 64, dropout: float = 0.3):
        super().__init__()
        self.l1 = SAGELayer(in_dim, hidden)
        self.l2 = SAGELayer(hidden, hidden)
        self.mlp = nn.Sequential(
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, 1),
        )

    def forward(self, x, edge_index, batch, n_graphs: int):
        h = self.l1(x, edge_index)
        h = self.l2(h, edge_index)
        pooled = torch.zeros(n_graphs, h.size(1), device=h.device)
        pooled.index_add_(0, batch, h)
        counts = torch.zeros(n_graphs, device=h.device)
        counts.index_add_(0, batch, torch.ones(batch.size(0), device=h.device))
        pooled = pooled / counts.clamp(min=1).unsqueeze(1)
        return self.mlp(pooled).squeeze(1)       # logits; sigmoid applied in loss / predict


def collate(graphs):
    """graphs: list of (x[list], edges[list of (s,d)], label). Returns tensors."""
    xs, eis, batch, ys = [], [], [], []
    off = 0
    for gi, (x, edges, y) in enumerate(graphs):
        xs.append(torch.tensor(x, dtype=torch.float32))
        if edges:
            e = torch.tensor(edges, dtype=torch.long).t() + off
        else:
            e = torch.zeros((2, 0), dtype=torch.long)
        eis.append(e)
        batch.append(torch.full((len(x),), gi, dtype=torch.long))
        ys.append(float(y))
        off += len(x)
    return (torch.cat(xs), torch.cat(eis, dim=1), torch.cat(batch),
            torch.tensor(ys), len(graphs))
