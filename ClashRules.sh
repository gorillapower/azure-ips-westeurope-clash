#!/bin/sh
. /usr/share/openclash/ruby.sh
. /usr/share/openclash/log.sh
. /lib/functions.sh

LOG_OUT "Configuring custom Clash rules..."
LOGTIME=$(date "+%Y-%m-%d %H:%M:%S")
LOG_FILE="/tmp/openclash.log"
CONFIG_FILE="$1"

echo "${LOGTIME} [ClashRules] Script started. CONFIG_FILE='${CONFIG_FILE}'" >> $LOG_FILE

if [ -z "$CONFIG_FILE" ]; then
  echo "${LOGTIME} [ClashRules] ERROR: CONFIG_FILE is empty — script is running from the WRONG HOOK." >> $LOG_FILE
  echo "${LOGTIME} [ClashRules] This script must be placed in 'Overwrite Settings', not 'Developer Settings / Firewall Rules'." >> $LOG_FILE
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "${LOGTIME} [ClashRules] ERROR: CONFIG_FILE path '${CONFIG_FILE}' does not exist on disk." >> $LOG_FILE
  exit 1
fi

echo "${LOGTIME} [ClashRules] CONFIG_FILE exists, proceeding with YAML modification." >> $LOG_FILE

ruby -ryaml -rYAML -I "/usr/share/openclash" -E UTF-8 -e "
  begin
    Value = YAML.load_file('$CONFIG_FILE')
    builtin_selector_names = %w[DIRECT REJECT GLOBAL FALLBACK]
    selectable_builtin_names = %w[DIRECT]

    # Per-device IPs for Azure region routing. Blank slots are skipped — set
    # these to your device's static-DHCP-leased IP. Each IP scopes the Azure
    # CIDR rules to that device only, so other household devices (e.g. Teams
    # calls on wife's phone) aren't routed via Azure region proxies.
    device_ips = [
      '',  # phone
      '10.0.0.227',  # macbook wifi
      '',  # macbook ethernet
    ].reject { |ip| ip.to_s.strip.empty? }

    ordered_unique = lambda do |items|
      items.each_with_object([]) do |item, memo|
        normalized = item.to_s.strip
        next if normalized.empty? || memo.include?(normalized)
        memo << normalized
      end
    end
    warn_and_skip = lambda do |message|
      File.open('$LOG_FILE', 'a') { |f| f.puts \"${LOGTIME} [ClashRules] WARN: #{message}. Skipping custom changes.\" }
    end

    proxy_groups = Value['proxy-groups']
    first_group = proxy_groups.is_a?(Array) ? proxy_groups[0] : nil
    main_selector_name = first_group && first_group['name'].to_s.strip
    raw_main_proxies = first_group && first_group['proxies'].is_a?(Array) ? first_group['proxies'] : nil

    if !proxy_groups.is_a?(Array) || proxy_groups.empty?
      warn_and_skip.call('proxy-groups is missing or empty')
    elsif main_selector_name.nil? || main_selector_name.empty?
      warn_and_skip.call('first proxy group name is missing')
    elsif raw_main_proxies.nil? || raw_main_proxies.empty?
      warn_and_skip.call('first proxy group proxies are missing or empty')
    else
      filtered_main_proxies = ordered_unique.call(
        raw_main_proxies.reject do |name|
          normalized = name.to_s.strip
          builtin_selector_names.include?(normalized) || normalized == main_selector_name
        end
      )

      if filtered_main_proxies.empty?
        warn_and_skip.call('first proxy group only contains built-in-like entries after filtering')
      else
        select_group_proxies = ordered_unique.call(selectable_builtin_names + [main_selector_name] + filtered_main_proxies)

        if device_ips.empty?
          File.open('$LOG_FILE', 'a') { |f| f.puts \"${LOGTIME} [ClashRules] device_ips is empty — Azure region rules not added.\" }
        end

      # =========================================================
      # PROXY GROUPS
      #   - url-test groups: skip if a same-named group already exists.
      #   - select groups:   create if missing, otherwise merge proxies
      #                      (union, dedup) into the existing group.
      # =========================================================

      [
        ['Azure_West_Europe', 'https://s3westeurope.blob.core.windows.net/public/latency-test.json', true],
        ['Azure_US_East',     'https://s3eastus.blob.core.windows.net/public/latency-test.json',     false],
        ['Azure_US_West',     'https://q9westus.blob.core.windows.net/public/latency-test.json',     false],
      ].each do |name, url, lazy|
        next if Value['proxy-groups'].find { |g| g['name'] == name }
        group = {
          'name'      => name,
          'type'      => 'url-test',
          'url'       => url,
          'interval'  => 300,
          'tolerance' => 50,
          'proxies'   => filtered_main_proxies
        }
        group['lazy'] = true if lazy
        Value['proxy-groups'].push(group)
      end

      ensure_select_group = lambda do |name|
        existing = Value['proxy-groups'].find { |g| g['name'] == name }
        if existing
          existing['proxies'] = ordered_unique.call((existing['proxies'] || []) + select_group_proxies)
        else
          Value['proxy-groups'].push({
            'name'    => name,
            'type'    => 'select',
            'proxies' => select_group_proxies
          })
        end
      end

      ['Azure', 'Microsoft', 'South Africa 🇿🇦', 'Brazil 🇧🇷', 'CrunchyRoll'].each do |name|
        ensure_select_group.call(name)
      end

      # =========================================================
      # RULE PROVIDERS
      # =========================================================

      Value['rule-providers'] ||= {}

      [
        ['Azure_West_Europe',     'azure_west_europe',     'ipcidr'],
        ['Azure_US_East',         'azure_us_east',         'ipcidr'],
        ['Azure_US_West',         'azure_us_west',         'ipcidr'],
        ['Azure_All',             'azure_cloud',           'ipcidr'],
        ['Microsoft_IPs',         'microsoft_ips',         'ipcidr'],
        ['Microsoft_M365_Domains','microsoft_m365_domains','domain'],
        ['Microsoft_Domains',     'microsoft_domains',     'domain'],
      ].each do |provider_name, slug, behavior|
        Value['rule-providers'][provider_name] = {
          'type'     => 'http',
          'behavior' => behavior,
          'url'      => \"https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/#{slug}.yaml\",
          'path'     => \"./rule_provider/#{slug}.yaml\",
          'interval' => 86400
        }
      end

      # =========================================================
      # RULES
      # Build prepend list in priority order (top = highest).
      # Final priority order:
      #   1. Banks/Suzano DIRECT (global)
      #   2. Microsoft_IPs → Microsoft (global, M365 Optimize/Allow IPs)
      #   3. Microsoft_M365_Domains → Microsoft (global, M365 hostname carve-out
      #      for Default-category endpoints whose IPs Microsoft doesn't pin —
      #      e.g. *.events.data.microsoft.com, parts of Trouter)
      #   4. Azure CIDR rules → Azure groups (device-scoped, IP-only)
      #   5. Microsoft_Domains → Microsoft (global, broader MS catch-all
      #      via blackmatrix7 — Bing, hotmail, telemetry, etc.)
      #   6. South Africa, CrunchyRoll, singaporeair (global)
      #   7. [subscription rules + catch-all]
      # =========================================================

      Value['rules'] ||= []
      prepend_rules = []

      # Banks/work apps that proxy IPs may break or block.
      prepend_rules.concat([
        'DOMAIN-SUFFIX,eqi.com.br,DIRECT',
        'DOMAIN-SUFFIX,btgpactual.com,DIRECT',
        'DOMAIN-SUFFIX,cloudpay.net,DIRECT',
        'DOMAIN-SUFFIX,suzano.com.br,DIRECT',
        'DOMAIN-SUFFIX,replicon.com,DIRECT',
        'DOMAIN-SUFFIX,service-now.com,DIRECT',
        'DOMAIN-SUFFIX,optionsreport.net,DIRECT',
        'DOMAIN-SUFFIX,concursolutions.com,DIRECT',
        'DOMAIN-SUFFIX,apptentive.com,DIRECT',
        'DOMAIN-SUFFIX,cloud.sap,DIRECT',
      ])

      # Microsoft 365 IPs — precise carve-out for M365 Optimize/Allow
      # endpoints (Microsoft pins these IPs for firewall allowlisting).
      # Placed above Azure rules: M365 IPs ⊂ Azure IPs, so without this
      # the Azure rules would grab M365 traffic. NO 'no-resolve' — we WANT
      # DNS resolution so hostname-based connections (teams.microsoft.com)
      # match here before the Azure CIDR rules below trigger resolution.
      prepend_rules << 'RULE-SET,Microsoft_IPs,Microsoft'

      # Microsoft 365 hostnames — covers M365 Default-category endpoints
      # whose IPs Microsoft doesn't pin (they land dynamically across
      # Azure). Examples: *.events.data.microsoft.com, parts of
      # *.teams.microsoft.com Trouter (pub-ent-jpea-05-t.trouter…).
      # These match Microsoft_IPs sometimes but not reliably, so without
      # this rule they leak into the Azure CIDR rules below.
      prepend_rules << 'RULE-SET,Microsoft_M365_Domains,Microsoft'

      # Azure — device-scoped via SRC-IP-CIDR. Only fires when the source
      # device is in device_ips. Routing is purely IP-based (Microsoft's
      # own recommendation: 'use Service Tags in place of FQDNs'). Azure_All
      # covers every Azure CIDR across all regions, so no hostname fallback
      # is needed.
      device_ips.each do |ip|
        # Region-specific: route to fast url-test group for that region.
        %w[Azure_West_Europe Azure_US_East Azure_US_West].each do |set|
          prepend_rules << \"AND,((SRC-IP-CIDR,#{ip}/32),(RULE-SET,#{set})),#{set}\"
        end
        # Catch-all: any other Azure region (Brazil South, Australia, etc.)
        # → generic Azure select group (you pick the proxy in the UI).
        prepend_rules << \"AND,((SRC-IP-CIDR,#{ip}/32),(RULE-SET,Azure_All)),Azure\"
      end

      # Microsoft Domains — broader catch-all (M365 endpoints ∪ blackmatrix7).
      # Below Azure rules so it doesn't hijack hostname-accessed Azure
      # resources (+.windows.net, +.azurewebsites.net, +.azure.com from
      # blackmatrix7) — those should still route via Azure region groups.
      # Catches non-Azure-IP MS traffic: Bing, hotmail, generic
      # microsoft.com, Edge, telemetry, etc.
      prepend_rules << 'RULE-SET,Microsoft_Domains,Microsoft'

      # South Africa — dice-live-eu carve-out must precede the broad
      # akamaized.net rule (RugbyPass streams via that host).
      prepend_rules.concat([
        'IP-CIDR,66.22.96.0/24,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,openeasy.io,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,easyequities.io,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,dice-live-eu.akamaized.net,' + main_selector_name,
        'DOMAIN-SUFFIX,akamaized.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamai.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,amazontrust.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamaietp.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamai-access.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akaetp.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akadns.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,segment.io,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,videoplaza.tv,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,bitmovin.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,dstv.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,dstv.stream,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,sdk.awswaf.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,permutive.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,hotjar.com,South Africa 🇿🇦',
        'GEOIP,ZA,South Africa 🇿🇦',
      ])

      # CrunchyRoll
      prepend_rules.concat([
        'DOMAIN-KEYWORD,crunchyroll,CrunchyRoll',
        'DOMAIN-SUFFIX,vrv.co,CrunchyRoll',
        'DOMAIN-SUFFIX,funimation.com,CrunchyRoll',
      ])

      # Misc AdHoc
      prepend_rules << 'DOMAIN-SUFFIX,singaporeair.com,' + main_selector_name
      prepend_rules << 'DOMAIN-SUFFIX,tenor.com,' + main_selector_name

      # Rule-level dedup — skip rules already present in the subscription
      # (exact string match). Preserves priority order of new rules.
      unique_prepend = prepend_rules.reject { |r| Value['rules'].include?(r) }
      Value['rules'].unshift(*unique_prepend)

      end
    end

    File.open('$CONFIG_FILE','w') {|f| YAML.dump(Value, f)}
    puts '${LOGTIME} Clash rules configured successfully'
  rescue Exception => e
    puts '${LOGTIME} Error: ' + e.message
  end
" 2>/dev/null >> $LOG_FILE

exit 0
