# Analysebericht: NPF `jail`-Qualifier bei eingehendem TCP (ohne VNET-Annahme)

## Ausgangspunkt (Ihre Klarstellung)
Sie nutzen **keinen** separaten VNET-Stack; Host und Jail teilen den Netzwerk-Stack. Erwartung ist korrekt:

- Regel `pass ... in ... jail "mail" ... port 10000` soll nur dann matchen,
  wenn der Ziel-Socket zu einem Prozess in Jail `mail` gehört.
- Damit soll verhindert werden, dass versehentlich ein Host-Prozess denselben Port "übernimmt" (Leakage).

## Verifizierte Semantik im Code

### 1) Jail-Check ist Teil des normalen Rule-Matchings
`npf_rule_inspect()` ruft immer `npf_rule_jail_match()` auf. Wenn das `false` liefert, matcht die Regel nicht.

### 2) Für inbound TCP/UDP wird der Ziel-Socket aktiv gesucht
`npf_rule_jail_match()` ruft für inbound `npf_rule_getsock_inbound()` auf.
Dort erfolgt Lookup über:

- `inpcb_lookup(&tcbtable, src,dst,ports...)`
- Fallback `inpcb_lookup_bound(&tcbtable, daddr, dport)`
- analog für UDP/IPv6

### 3) Harte Bedingung bei explizitem `jail`
Wenn kein Socket (oder keine Socket-Credential) gefunden wird:

- Rückgabe ist `jail_name == NULL`.
- Bei `jail "mail"` also **immer false**.

### 4) Jail-Name-Match selbst
Mit gefundenem Socket wird `so->so_cred` gegen den konfigurierten Jail-Namen geprüft (`secmodel_eval(... cred-matches ...)`).
Der Name muss exakt auf die Jail-Entry des Credentials passen.

## Wichtige Beobachtung: Warum das auch ohne VNET scheitern kann
Auch im **gemeinsamen Stack** gibt es mehrere kritische Stellen:

1. **Lookup findet nicht den erwarteten Listener**
   - Der Fallback `inpcb_lookup_bound(laddr,lport)` unterscheidet nicht nach Jail-Name.
   - Er liefert den ersten passenden PCB für Adresse/Port.
   - Bei Mehrdeutigkeit (z. B. mehrere Bound-Sockets, Wildcard/konkrete Adresse, Reordering in Hash-Listen)
     kann ein anderer Socket als der erwartete genommen werden.

2. **Address-Scope-Mismatch zwischen Testziel und Jail-Bindings**
   - `nc -l 10000` in einer Jail kann effektiv nur auf erlaubten Jail-Adressen lauschen.
   - Wenn der Test auf eine andere Host-IP zielt als die Jail-IP, kann der Socket-Lookup leer laufen.
   - Mit explizitem `jail` führt das zwingend zu "kein Match".

3. **Zeitpunkt/Hook-Kontext vs. Socket-Auflösung**
   - NPF arbeitet im pfil-Pfad auf AF-Ebene.
   - Der Jail-Qualifier setzt voraus, dass im jeweiligen Hook-Kontext die PCB-Auflösung bereits eindeutig gelingt.
   - Wenn das für das konkrete Paket nicht gelingt, scheitert `jail`-Match unabhängig von Ihrer Policy-Absicht.

4. **Jail-Name/Credential-Drift**
   - Der Vergleich ist strikt gegen `entry->je_name`.
   - Schon ein Namensmismatch (historisch umbenannt, anderes Label als gedacht) liefert `false`.

## Zu Ihrer Beobachtung „mit jail qualifier gar nichts, ohne qualifier teils ja"
Das ist mit dem Code vereinbar:

- **Mit `jail "mail"`**: Socket muss aufgelöst werden *und* Credential muss zu `mail` passen.
- **Ohne `jail`**: diese harte Einschränkung fällt weg; die Regel kann bei reinem 5-Tuple/Interface-Match greifen.

Dass Ihr `nc` in der Jail trotzdem nicht erreicht wird, spricht dann eher für
Adress-/Routing-/Bind-Kontext oder dafür, dass Lookup/Delivery nicht zum erwarteten Socket führt.

## Warum „kein npflog“ ein separates Warnsignal ist
Bei Ihrer Regelreihenfolge würde bei Nicht-Match der `pass ... jail ...`-Regel grundsätzlich `block all apply "logpkt"` greifen.
Wenn **gar nichts** im `npflog0` erscheint, liegt häufig zusätzlich ein Pfadproblem vor (nicht derselbe Filterpunkt/Interface/Richtung),
nicht nur ein Jail-Mismatch.

## Konkrete technische Verdachtsliste (ohne VNET)

1. **Socket-Resolution ist nicht eindeutig / liefert falschen PCB**
   (Designgrenze des aktuellen Lookup-Pfads ohne Jail-Disambiguierung).
2. **Ziel-IP im Test gehört nicht zur effektiven Jail-Listener-Bindung**.
3. **Paket trifft nicht den von Ihnen beobachteten NPF-Hook/`npflog0`-Pfad**.
4. **Jail-Name im Rule-Qualifier entspricht nicht exakt dem Credential-Jail-Namen**.

## Kritische Code-Stellen (für Bug-Report relevant)

- `sys/net/npf/npf_ruleset.c`
  - `npf_rule_inspect()`
  - `npf_rule_jail_match()`
  - `npf_rule_getsock_inbound()`
- `sys/netinet/in_pcb.c`
  - `inpcb_lookup()`
  - `inpcb_lookup_bound()`
- `sys/secmodel/jail/secmodel_jail.c`
  - `secmodel_jail_cred_matches()`
- `usr.sbin/npf/npfctl/npf.conf.5`
  - dokumentierte Inbound-Einschränkungen des `jail`-Qualifiers

## Vorschlag für einen präzisen Upstream-Bugtitel
"NPF inbound jail qualifier depends on ambiguous PCB lookup (`inpcb_lookup_bound`) and may fail/misclassify shared-stack jail listeners"

## Minimale Repro-Checks für saubere Eingrenzung

1. Verifizieren, auf **welcher Ziel-IP** der Jail-Listener tatsächlich lauscht (`sockstat -4 -l` im Host und in Jail).
2. Test auf genau diese Ziel-IP wiederholen.
3. Parallel dumpen auf `wm0` und `npflog0`, um zu sehen, ob Paket den gleichen Hook passiert.
4. Optional zweiten Listener (Host vs. Jail, gleicher Port) aufbauen, um Mehrdeutigkeit im PCB-Lookup sichtbar zu machen.

