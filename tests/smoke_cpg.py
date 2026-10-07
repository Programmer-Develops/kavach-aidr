from kavach.vuln_gnn.cpg import build_cpg
from kavach.vuln_gnn.graphsage import VulnGraphSAGE, collate

bad = '''
def get_user(name):
    q = "SELECT * FROM u WHERE n='%s'" % name
    cur.execute(q)
    return cur.fetchone()
'''
good = '''
def get_user(name):
    cur.execute("SELECT * FROM u WHERE n=?", (name,))
    return cur.fetchone()
'''
gb, gg = build_cpg(bad), build_cpg(good)
for g in (gb, gg):
    print("nodes", len(g.x), "edges", len(g.edges), "sinks", g.n_sink, "tainted sinks", g.n_tainted_sink)
m = VulnGraphSAGE()
x, ei, batch, y, n = collate([(gb.x, gb.edges, 1), (gg.x, gg.edges, 0)])
print("logits", m(x, ei, batch, n).shape, "params", sum(p.numel() for p in m.parameters()))
