<template>
  <div class="settings-page">
    <a-space direction="vertical" :size="20" fill>
      <!-- VPN 功能配置 -->
      <a-card :bordered="false">
        <template #title>
          <div class="card-header">
            <h3>系统设置</h3>
            <p>配置VPN功能、性能优化和LDAP认证等系统功能。</p>
          </div>
        </template>

        <a-tabs default-active-key="compression">
          <!-- 流量压缩配置 -->
          <a-tab-pane key="compression" title="流量压缩">
            <a-form :model="compressionForm" layout="vertical" @submit="handleCompressionSubmit">
              <a-form-item label="启用流量压缩">
                <a-switch v-model="compressionForm.enable_compression" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    启用后可以节省30-70%的带宽，但会增加少量CPU开销
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="compressionForm.enable_compression">
                <a-form-item label="压缩算法" required>
                  <a-select v-model="compressionForm.compression_type" placeholder="选择压缩算法">
                    <a-option value="lz4">LZ4 (快速，低CPU占用，推荐)</a-option>
                    <a-option value="gzip">Gzip (高压缩比，CPU占用较高)</a-option>
                  </a-select>
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      OpenConnect客户端仅支持LZ4，Gzip会自动映射为LZ4
                    </a-typography-text>
                  </template>
                </a-form-item>
              </template>

              <a-form-item>
                <a-button type="primary" @click="handleCompressionSubmit" :loading="compressionLoading">
                  保存配置
                </a-button>
              </a-form-item>
            </a-form>
          </a-tab-pane>

          <!-- 性能优化配置 -->
          <a-tab-pane key="performance" title="性能优化">
            <a-form :model="performanceForm" layout="vertical" @submit="handlePerformanceSubmit">
              <a-form-item label="启用策略缓存">
                <a-switch v-model="performanceForm.enable_policy_cache" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    启用后可以缓存策略执行结果，减少重复检查，提升性能1.5-3x
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="performanceForm.enable_policy_cache">
                <a-form-item label="缓存大小">
                  <a-input-number
                    v-model="performanceForm.cache_size"
                    :min="100"
                    :max="10000"
                    placeholder="默认: 1000"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      缓存条目数量，建议值：1000-5000
                    </a-typography-text>
                  </template>
                </a-form-item>
              </template>

              <a-form-item label="启用IP匹配优化（Trie树）">
                <a-switch v-model="performanceForm.enable_ip_trie" :disabled="true" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    已默认启用，使用Trie树优化IP匹配，性能提升10-100x
                  </a-typography-text>
                </template>
              </a-form-item>

              <a-form-item label="启用策略索引">
                <a-switch v-model="performanceForm.enable_policy_index" :disabled="true" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    已默认启用，按协议、端口分组索引，性能提升2-5x
                  </a-typography-text>
                </template>
              </a-form-item>

              <a-alert type="info" style="margin-bottom: 16px">
                <template #title>性能优化说明</template>
                <div style="font-size: 12px">
                  <p><strong>策略缓存</strong>：缓存策略执行结果，适合重复流量场景</p>
                  <p><strong>IP匹配优化</strong>：使用Trie树，复杂度从O(n)降到O(32)</p>
                  <p><strong>策略索引</strong>：按协议、端口分组，快速过滤不相关策略</p>
                  <p><strong>综合性能提升</strong>：20-90x（取决于策略数量和流量模式）</p>
                </div>
              </a-alert>

              <a-form-item>
                <a-button type="primary" @click="handlePerformanceSubmit" :loading="performanceLoading">
                  保存配置
                </a-button>
              </a-form-item>
            </a-form>
          </a-tab-pane>

          <!-- 分布式同步 -->
          <a-tab-pane key="distributed-sync" title="分布式同步">
            <a-form :model="distributedForm" layout="vertical" @submit="handleDistributedSyncSubmit">
              <a-form-item label="启用分布式同步">
                <a-switch v-model="distributedForm.enable_distributed_sync" />
                <template #extra>
              <a-typography-text type="secondary" style="font-size: 12px">
                默认关闭，仅多节点/集群时建议开启；单节点保持关闭减少开销
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="distributedForm.enable_distributed_sync">
                <a-form-item label="全量同步间隔（秒）">
                  <a-input-number
                    v-model="distributedForm.sync_interval"
                    :min="5"
                    :max="3600"
                    placeholder="默认: 120"
                    style="width: 100%"
                  />
                  <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    周期性全量同步，用于校正遗漏或漂移（多节点建议 ≥120s）
                  </a-typography-text>
                  </template>
                </a-form-item>

                <a-form-item label="变更检测间隔（秒）">
                  <a-input-number
                    v-model="distributedForm.change_check_interval"
                    :min="1"
                    :max="600"
                    placeholder="默认: 10"
                    style="width: 100%"
                  />
                  <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    快速增量同步频率，越低越实时但会增加数据库查询（建议 ≥10s）
                  </a-typography-text>
                  </template>
                </a-form-item>
              </template>

              <a-alert type="info" style="margin-bottom: 16px">
                <template #title>多节点同步说明</template>
                <div style="font-size: 12px">
                  <p>默认关闭：单节点或调试场景保持关闭，避免额外查询。</p>
                  <p>多节点开启后：每<span style="font-weight: 600">{{ distributedForm.change_check_interval || 10 }}</span>s 增量检测，<span style="font-weight: 600">{{ distributedForm.sync_interval || 120 }}</span>s 全量校正。</p>
                </div>
              </a-alert>

              <a-form-item>
                <a-button type="primary" @click="handleDistributedSyncSubmit" :loading="distributedLoading">
                  保存配置
                </a-button>
              </a-form-item>
            </a-form>
          </a-tab-pane>

          <!-- 安全防护配置 -->
          <a-tab-pane key="security" title="安全防护">
            <a-form :model="securityForm" layout="vertical" @submit="handleSecuritySubmit">
              <a-alert type="warning" style="margin-bottom: 16px">
                <template #title>eBPF 防护说明</template>
                <div style="font-size: 12px">
                  <p>安全防护功能使用 eBPF 在内核空间实现，提供高性能的流量限流和攻击防护。</p>
                  <p><strong>限流功能</strong>：基于令牌桶算法，在 eBPF 内核空间执行，延迟 <1μs</p>
                  <p><strong>DDoS 防护</strong>：自动检测异常流量模式，超过阈值自动封禁</p>
                  <p><strong>连接限制</strong>：限制每个 IP 的最大连接数和连接速率</p>
                </div>
              </a-alert>

              <a-divider orientation="left">登录控制</a-divider>
              <a-form-item label="允许同一账号多端同时在线">
                <a-switch v-model="securityForm.allow_multi_client_login" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    关闭后，同一账号仅允许一个客户端在线；开启则允许多端同时登录
                  </a-typography-text>
                </template>
              </a-form-item>

              <a-divider orientation="left">流量限流</a-divider>

              <a-form-item label="启用流量限流">
                <a-switch v-model="securityForm.enable_rate_limit" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    启用后，系统会在 eBPF 内核空间对流量进行限流，防止单个 IP 或用户占用过多带宽
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="securityForm.enable_rate_limit">
                <a-form-item label="每 IP 限流（包/秒）">
                  <a-input-number
                    v-model="securityForm.rate_limit_per_ip"
                    :min="1"
                    :max="100000"
                    placeholder="默认: 1000"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      每个 IP 地址每秒允许的最大数据包数量
                    </a-typography-text>
                  </template>
                </a-form-item>

                <a-form-item label="每用户限流（字节/秒）">
                  <a-input-number
                    v-model="securityForm.rate_limit_per_user"
                    :min="1024"
                    :max="1073741824"
                    placeholder="默认: 10485760 (10MB/s)"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      每个用户每秒允许的最大字节数（带宽限制）
                    </a-typography-text>
                  </template>
                </a-form-item>
              </template>

              <a-divider orientation="left">DDoS 防护</a-divider>

              <a-form-item label="启用 DDoS 防护">
                <a-switch v-model="securityForm.enable_ddos_protection" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    启用后，系统会自动检测并阻止 DDoS 攻击流量
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="securityForm.enable_ddos_protection">
                <a-form-item label="DDoS 检测阈值（包/秒）">
                  <a-input-number
                    v-model="securityForm.ddos_threshold"
                    :min="100"
                    :max="1000000"
                    placeholder="默认: 10000"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      单个 IP 每秒超过此阈值的数据包数将被视为 DDoS 攻击
                    </a-typography-text>
                  </template>
                </a-form-item>

                <a-form-item label="封禁时长（秒）">
                  <a-input-number
                    v-model="securityForm.ddos_block_duration"
                    :min="60"
                    :max="3600"
                    placeholder="默认: 300 (5分钟)"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      检测到 DDoS 攻击后，封禁该 IP 的时长（60-3600 秒）
                    </a-typography-text>
                  </template>
                </a-form-item>
              </template>

              <a-divider orientation="left">密码爆破防护</a-divider>

              <a-form-item label="启用密码爆破防护">
                <a-switch v-model="securityForm.enable_bruteforce_protection" />
                <template #extra>
                  <a-typography-text type="secondary" style="font-size: 12px">
                    启用后，系统会跟踪每个 IP 的登录失败次数，超过阈值后自动封禁该 IP
                  </a-typography-text>
                </template>
              </a-form-item>

              <template v-if="securityForm.enable_bruteforce_protection">
                <a-form-item label="最大失败次数">
                  <a-input-number
                    v-model="securityForm.max_login_attempts"
                    :min="3"
                    :max="20"
                    placeholder="默认: 5"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      在时间窗口内，单个 IP 允许的最大登录失败次数。超过此次数将被封禁
                    </a-typography-text>
                  </template>
                </a-form-item>

                <a-form-item label="时间窗口（秒）">
                  <a-input-number
                    v-model="securityForm.login_attempt_window"
                    :min="60"
                    :max="3600"
                    placeholder="默认: 300 (5分钟)"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      在此时间窗口内的失败次数会被累计。例如：5分钟内失败5次则封禁
                    </a-typography-text>
                  </template>
                </a-form-item>

                <a-form-item label="封禁时长（秒）">
                  <a-input-number
                    v-model="securityForm.login_lockout_duration"
                    :min="60"
                    :max="86400"
                    placeholder="默认: 900 (15分钟)"
                    style="width: 100%"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      检测到密码爆破后，封禁该 IP 的时长（60-86400 秒，即1分钟到24小时）
                    </a-typography-text>
                  </template>
                </a-form-item>

                <a-alert type="info" style="margin-bottom: 16px">
                  <template #title>密码爆破防护说明</template>
                  <div style="font-size: 12px">
                    <p><strong>工作原理</strong>：系统会跟踪每个 IP 的登录失败次数，在时间窗口内累计。</p>
                    <p><strong>示例</strong>：如果设置为"5分钟内失败5次"，那么：</p>
                    <ul style="margin: 8px 0; padding-left: 20px">
                      <li>正常用户：输入错误密码 1-2 次不会触发封禁</li>
                      <li>密码爆破：连续尝试 5 次错误密码 → 立即封禁 15 分钟</li>
                      <li>封禁期间：该 IP 的所有登录请求都会被拒绝</li>
                    </ul>
                    <p><strong>建议值</strong>：5次失败 / 5分钟窗口 / 15分钟封禁（默认值）</p>
                  </div>
                </a-alert>
              </template>

              <a-form-item>
                <a-button type="primary" @click="handleSecuritySubmit" :loading="securityLoading">
                  保存配置
                </a-button>
              </a-form-item>
            </a-form>
          </a-tab-pane>

          <!-- 审计日志协议配置 -->
          <a-tab-pane key="audit-log" title="审计日志">
            <a-form :model="auditLogForm" layout="vertical" @submit="handleAuditLogSubmit">
              <a-alert type="info" style="margin-bottom: 16px">
                <template #title>审计日志协议设置</template>
                <div style="font-size: 12px">
                  <p>选择需要记录审计日志的协议类型。默认开启常用协议（TCP、UDP、HTTP、HTTPS等），DNS和ICMP默认关闭以减少日志量。</p>
                  <p><strong>建议</strong>：根据实际需求开启协议，避免记录过多日志导致数据库压力过大。</p>
                </div>
              </a-alert>

              <a-divider orientation="left">常用协议（默认开启）</a-divider>
              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.tcp">TCP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        传输控制协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.udp">UDP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        用户数据报协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
              </a-row>

              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.http">HTTP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        超文本传输协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.https">HTTPS</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        安全超文本传输协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
              </a-row>

              <a-divider orientation="left">其他协议</a-divider>
              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.ssh">SSH</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        安全外壳协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.ftp">FTP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        文件传输协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
              </a-row>

              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.smtp">SMTP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        简单邮件传输协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.mysql">MySQL</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        MySQL数据库协议
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
              </a-row>

              <a-divider orientation="left">高频协议（默认关闭）</a-divider>
              <a-alert type="warning" style="margin-bottom: 16px">
                <template #title>注意</template>
                <div style="font-size: 12px">
                  <p>以下协议会产生大量日志，建议仅在需要时开启：</p>
                </div>
              </a-alert>

              <a-row :gutter="16">
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.dns">DNS</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        域名系统查询（会产生大量日志）
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item>
                    <a-checkbox v-model="auditLogForm.enabled_protocols.icmp">ICMP</a-checkbox>
                    <template #extra>
                      <a-typography-text type="secondary" style="font-size: 12px">
                        Ping/ICMP协议（会产生大量日志）
                      </a-typography-text>
                    </template>
                  </a-form-item>
                </a-col>
              </a-row>

              <a-form-item>
                <a-button type="primary" @click="handleAuditLogSubmit" :loading="auditLogLoading">
                  保存配置
                </a-button>
              </a-form-item>
            </a-form>
          </a-tab-pane>

          <!-- LDAP 认证配置 -->
          <a-tab-pane key="ldap" title="LDAP 认证">
            <a-form :model="formData" layout="vertical" @submit="handleSubmit">
          <a-form-item label="启用 LDAP 认证">
            <a-switch v-model="formData.enabled" />
            <template #extra>
              <a-typography-text type="secondary" style="font-size: 12px">
                启用后，用户可以使用 LDAP 账号登录
              </a-typography-text>
            </template>
          </a-form-item>

          <template v-if="formData.enabled">
            <a-divider orientation="left">LDAP 服务器配置</a-divider>

            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="LDAP 服务器地址" required>
                  <a-input
                    v-model="formData.host"
                    placeholder="例如: ldap.company.com"
                  />
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="端口" required>
                  <a-input-number
                    v-model="formData.port"
                    :min="1"
                    :max="65535"
                    placeholder="389 或 636 (LDAPS)"
                    style="width: 100%"
                  />
                </a-form-item>
              </a-col>
            </a-row>

            <a-form-item label="使用 SSL/TLS">
              <a-switch v-model="formData.use_ssl" />
              <template #extra>
                <a-typography-text type="secondary" style="font-size: 12px">
                  LDAPS 使用 636 端口
                </a-typography-text>
              </template>
            </a-form-item>

            <a-form-item label="跳过 TLS 证书验证">
              <a-switch v-model="formData.skip_tls_verify" />
            </a-form-item>

            <a-divider orientation="left">绑定账号配置</a-divider>

            <a-form-item label="绑定 DN" required>
              <a-input
                v-model="formData.bind_dn"
                placeholder="例如: cn=admin,dc=company,dc=com"
              />
              <template #extra>
                <a-typography-text type="secondary" style="font-size: 12px">
                  用于搜索用户的 LDAP 管理员账号
                </a-typography-text>
              </template>
            </a-form-item>

            <a-form-item label="绑定密码" required>
              <a-input-password
                v-model="formData.bind_password"
                placeholder="留空则不修改密码"
                show-password-on="click"
              />
            </a-form-item>

            <a-divider orientation="left">用户搜索配置</a-divider>

            <a-form-item label="Base DN" required>
              <a-input
                v-model="formData.base_dn"
                placeholder="例如: ou=users,dc=company,dc=com"
              />
              <template #extra>
                <a-typography-text type="secondary" style="font-size: 12px">
                  用户搜索的基础 DN
                </a-typography-text>
              </template>
            </a-form-item>

            <a-form-item label="用户过滤器" required>
              <a-input
                v-model="formData.user_filter"
                placeholder="例如: (uid=%s) 或 (sAMAccountName=%s)"
              />
              <template #extra>
                <a-typography-text type="secondary" style="font-size: 12px">
                  OpenLDAP 使用 (uid=%s)，Active Directory 使用 (sAMAccountName=%s)
                </a-typography-text>
              </template>
            </a-form-item>

            <a-form-item label="管理员组 DN">
              <a-input
                v-model="formData.admin_group"
                placeholder="例如: cn=vpn-admins,ou=groups,dc=company,dc=com"
              />
              <template #extra>
                <a-typography-text type="secondary" style="font-size: 12px">
                  可选，该组内的用户将自动获得管理员权限
                </a-typography-text>
              </template>
            </a-form-item>

            <a-divider orientation="left">LDAP 属性映射（高级配置）</a-divider>
            <a-typography-text type="secondary" style="font-size: 12px; margin-bottom: 16px; display: block">
              不同公司的LDAP服务器属性名可能不同，可以在此配置属性映射。留空则使用默认值或从UserFilter自动推断。
            </a-typography-text>

            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="用户名属性">
                  <a-input
                    v-model="attributeMapping.username"
                    placeholder="例如: uid, sAMAccountName, cn"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      留空则从UserFilter自动推断
                    </a-typography-text>
                  </template>
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="邮箱属性">
                  <a-input
                    v-model="attributeMapping.email"
                    placeholder="默认: mail"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      默认值: mail
                    </a-typography-text>
                  </template>
                </a-form-item>
              </a-col>
            </a-row>

            <a-row :gutter="16">
              <a-col :span="12">
                <a-form-item label="全名属性">
                  <a-input
                    v-model="attributeMapping.full_name"
                    placeholder="默认: displayName"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      默认值: displayName（如果为空则使用cn）
                    </a-typography-text>
                  </template>
                </a-form-item>
              </a-col>
              <a-col :span="12">
                <a-form-item label="组成员属性">
                  <a-input
                    v-model="attributeMapping.member_of"
                    placeholder="默认: memberOf"
                  />
                  <template #extra>
                    <a-typography-text type="secondary" style="font-size: 12px">
                      默认值: memberOf
                    </a-typography-text>
                  </template>
                </a-form-item>
              </a-col>
            </a-row>
          </template>

          <a-form-item>
            <a-space>
              <a-button type="primary" @click="handleSubmit" :loading="submitLoading">
                保存配置
              </a-button>
              <a-button @click="handleTest" :loading="testLoading" :disabled="!formData.enabled">
                测试连接
              </a-button>
              <a-button @click="showAuthTestModal = true" :disabled="!formData.enabled">
                测试认证
              </a-button>
              <a-button @click="handleSyncUsers" :loading="syncLoading" :disabled="!formData.enabled" type="outline">
                同步用户
              </a-button>
            </a-space>
          </a-form-item>
        </a-form>
          </a-tab-pane>
        </a-tabs>
      </a-card>

      <!-- LDAP 认证测试弹窗 -->
      <a-modal
        v-model:visible="showAuthTestModal"
        title="LDAP 用户认证测试"
        :width="500"
        @ok="handleAuthTest"
        @cancel="() => { authTestForm.username = ''; authTestForm.password = '' }"
        :ok-loading="authTestLoading"
        ok-text="测试"
        cancel-text="取消"
      >
        <a-form :model="authTestForm" layout="vertical">
          <a-form-item label="用户名" required>
            <a-input
              v-model="authTestForm.username"
              placeholder="请输入要测试的LDAP用户名"
              @press-enter="handleAuthTest"
            />
            <template #extra>
              <a-typography-text type="secondary" style="font-size: 12px">
                输入LDAP中的用户名（不是DN），系统会根据UserFilter搜索用户
              </a-typography-text>
            </template>
          </a-form-item>
          <a-form-item label="密码" required>
            <a-input-password
              v-model="authTestForm.password"
              placeholder="请输入用户密码"
              @press-enter="handleAuthTest"
            />
            <template #extra>
              <a-typography-text type="secondary" style="font-size: 12px">
                输入该用户在LDAP中的密码，用于验证认证是否正常
              </a-typography-text>
            </template>
          </a-form-item>
        </a-form>
        <template #footer>
          <a-space>
            <a-button @click="showAuthTestModal = false">取消</a-button>
            <a-button type="primary" @click="handleAuthTest" :loading="authTestLoading">
              测试认证
            </a-button>
          </a-space>
        </template>
      </a-modal>

      <!-- LDAP 认证测试成功弹窗 -->
      <a-modal
        v-model:visible="showAuthTestResultModal"
        title="认证测试成功"
        :width="500"
      >
        <div style="line-height: 1.8;">
          <p><strong>用户信息：</strong></p>
          <p>用户名: {{ authTestResult.user?.username }} {{ authTestResult.user?.is_admin ? '（管理员）' : '（普通用户）' }}</p>
          <p>DN: {{ authTestResult.user?.dn || '-' }}</p>
          <p v-if="authTestResult.user?.email">邮箱: {{ authTestResult.user.email }}</p>
          <p v-if="authTestResult.user?.full_name">姓名: {{ authTestResult.user.full_name }}</p>
          <p style="margin-top: 10px; color: #52c41a;">{{ authTestResult.message }}</p>
        </div>
        <template #footer>
          <a-button type="primary" @click="showAuthTestResultModal = false">确定</a-button>
        </template>
      </a-modal>

      <!-- LDAP 用户同步结果弹窗 -->
      <a-modal
        v-model:visible="showSyncResultModal"
        title="用户同步完成"
        :width="500"
      >
        <div style="line-height: 1.8;">
          <p style="color: #52c41a; font-weight: bold;">{{ syncResult.message }}</p>
          <p v-if="syncResultDetails.length > 0">{{ syncResultDetails.join('，') }}</p>
          <div v-if="syncResult.error_details && syncResult.error_details.length > 0" style="margin-top: 10px;">
            <p style="color: #ff4d4f;"><strong>错误详情：</strong></p>
            <ul style="margin: 5px 0; padding-left: 20px;">
              <li v-for="(err, index) in syncResult.error_details" :key="index" style="margin: 3px 0;">{{ err }}</li>
            </ul>
          </div>
        </div>
        <template #footer>
          <a-button type="primary" @click="showSyncResultModal = false">确定</a-button>
        </template>
      </a-modal>
    </a-space>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ldapApi, type UpdateLDAPConfigRequest, type LDAPAuthTestRequest, type LDAPSyncResponse, type LDAPAttributeMapping } from '@/api/ldap'
import { Message, Modal } from '@arco-design/web-vue'
import request from '@/api/request'

const submitLoading = ref(false)
const testLoading = ref(false)
const authTestLoading = ref(false)
const syncLoading = ref(false)
const showAuthTestModal = ref(false)
const showAuthTestResultModal = ref(false)
const showSyncResultModal = ref(false)
const previousLDAPEnabled = ref(false) // 记录LDAP之前是否启用
const authTestResult = reactive<{
  user?: {
    username?: string
    dn?: string
    email?: string
    full_name?: string
    is_admin?: boolean
  }
  message?: string
}>({
  user: undefined,
  message: '',
})
const syncResult = reactive<LDAPSyncResponse>({
  success: false,
  message: '',
  total: undefined,
  created: undefined,
  updated: undefined,
  errors: undefined,
  error_details: [],
})
const syncResultDetails = ref<string[]>([])
const authTestForm = reactive<LDAPAuthTestRequest>({
  username: '',
  password: '',
})
const compressionLoading = ref(false)
const performanceLoading = ref(false)
const securityLoading = ref(false)
const distributedLoading = ref(false)
const auditLogLoading = ref(false)

// 流量压缩配置
const compressionForm = reactive({
  enable_compression: false,
  compression_type: 'lz4',
})

// DNS拦截器配置已写死在代码中，不需要配置

// 性能优化配置
const performanceForm = reactive({
  enable_policy_cache: true,
  cache_size: 1000,
  enable_ip_trie: true, // 默认启用，不可修改
  enable_policy_index: true, // 默认启用，不可修改
})

// 分布式同步配置
const distributedForm = reactive({
  enable_distributed_sync: false,
  sync_interval: 120,
  change_check_interval: 10,
})

// 安全防护配置（默认禁用限流）
const securityForm = reactive({
  enable_rate_limit: false,
  rate_limit_per_ip: 1000,
  rate_limit_per_user: 10485760, // 10MB/s
  allow_multi_client_login: true,
  enable_ddos_protection: false,
  ddos_threshold: 10000,
  ddos_block_duration: 300, // 5 minutes
  enable_bruteforce_protection: true,
  max_login_attempts: 5,
  login_lockout_duration: 900, // 15 minutes
  login_attempt_window: 300, // 5 minutes
})

// 审计日志协议配置
const auditLogForm = reactive({
  enabled_protocols: {
    tcp: true,
    udp: true,
    http: true,
    https: true,
    ssh: true,
    ftp: true,
    smtp: true,
    mysql: true,
    dns: false,
    icmp: false,
  } as Record<string, boolean>,
})

const formData = reactive<UpdateLDAPConfigRequest>({
  enabled: false,
  host: '',
  port: 389,
  use_ssl: false,
  bind_dn: '',
  bind_password: '',
  base_dn: '',
  user_filter: '(uid=%s)',
  admin_group: '',
  skip_tls_verify: false,
  attribute_mapping: '',
})

// LDAP属性映射配置
const attributeMapping = reactive<LDAPAttributeMapping>({
  username: '',
  email: '',
  full_name: '',
  member_of: '',
})

const fetchConfig = async () => {
  try {
    const config = await ldapApi.getConfig()
    // 记录之前的LDAP启用状态
    previousLDAPEnabled.value = config.enabled
    formData.enabled = config.enabled
    formData.host = config.host || ''
    formData.port = config.port || 389
    formData.use_ssl = config.use_ssl || false
    formData.bind_dn = config.bind_dn || ''
    formData.base_dn = config.base_dn || ''
    formData.user_filter = config.user_filter || '(uid=%s)'
    formData.admin_group = config.admin_group || ''
    formData.skip_tls_verify = config.skip_tls_verify || false
    // 密码不返回，保持为空
    formData.bind_password = ''
    
    // 解析属性映射配置
    if (config.attribute_mapping) {
      try {
        const mapping = JSON.parse(config.attribute_mapping) as LDAPAttributeMapping
        attributeMapping.username = mapping.username || ''
        attributeMapping.email = mapping.email || ''
        attributeMapping.full_name = mapping.full_name || ''
        attributeMapping.member_of = mapping.member_of || ''
      } catch (e) {
        console.error('Failed to parse attribute mapping:', e)
      }
    } else {
      // 重置为默认值
      attributeMapping.username = ''
      attributeMapping.email = ''
      attributeMapping.full_name = ''
      attributeMapping.member_of = ''
    }
    
    // 获取性能优化配置（完全依赖后端返回值）
    try {
      const perfConfig = await request.get('/settings/performance')
      if (perfConfig) {
        performanceForm.enable_policy_cache = perfConfig.enable_policy_cache
        performanceForm.cache_size = perfConfig.cache_size
      }
    } catch (error) {
      // 如果API失败，使用默认值（与后端一致）
      console.log('Performance settings API not available, using defaults')
      performanceForm.enable_policy_cache = true
      performanceForm.cache_size = 1000
    }

    // 获取分布式同步配置（完全依赖后端返回值）
    try {
      const syncConfig = await request.get('/settings/distributed-sync')
      if (syncConfig) {
        distributedForm.enable_distributed_sync = syncConfig.enable_distributed_sync
        distributedForm.sync_interval = syncConfig.sync_interval
        distributedForm.change_check_interval = syncConfig.change_check_interval
      }
    } catch (error) {
      // 如果API失败，使用默认值（与后端一致）
      console.log('Distributed sync settings API not available, using defaults')
      distributedForm.enable_distributed_sync = false
      distributedForm.sync_interval = 120
      distributedForm.change_check_interval = 10
    }

    // 获取安全防护配置（完全依赖后端返回值）
    try {
      const secConfig = await request.get('/settings/security')
      if (secConfig) {
        securityForm.enable_rate_limit = secConfig.enable_rate_limit
        securityForm.rate_limit_per_ip = secConfig.rate_limit_per_ip
        securityForm.rate_limit_per_user = secConfig.rate_limit_per_user
        securityForm.allow_multi_client_login = secConfig.allow_multi_client_login
        securityForm.enable_ddos_protection = secConfig.enable_ddos_protection
        securityForm.ddos_threshold = secConfig.ddos_threshold
        securityForm.ddos_block_duration = secConfig.ddos_block_duration
        securityForm.enable_bruteforce_protection = secConfig.enable_bruteforce_protection
        securityForm.max_login_attempts = secConfig.max_login_attempts
        securityForm.login_lockout_duration = secConfig.login_lockout_duration
        securityForm.login_attempt_window = secConfig.login_attempt_window
      }
    } catch (error) {
      // 如果API失败，使用默认值（与后端一致）
      console.log('Security settings API not available, using defaults')
      securityForm.enable_rate_limit = false
      securityForm.rate_limit_per_ip = 1000
      securityForm.rate_limit_per_user = 10485760
      securityForm.allow_multi_client_login = true
      securityForm.enable_ddos_protection = false
      securityForm.ddos_threshold = 10000
      securityForm.ddos_block_duration = 300
      securityForm.enable_bruteforce_protection = true
      securityForm.max_login_attempts = 5
      securityForm.login_lockout_duration = 900
      securityForm.login_attempt_window = 300
    }

    // 获取审计日志协议配置
    try {
      const auditConfig = await request.get('/settings/audit-log')
      if (auditConfig && auditConfig.enabled_protocols) {
        // 合并默认值和服务器返回的值
        Object.keys(auditLogForm.enabled_protocols).forEach((key) => {
          if (auditConfig.enabled_protocols[key] !== undefined) {
            auditLogForm.enabled_protocols[key] = auditConfig.enabled_protocols[key]
          }
        })
      }
    } catch (error) {
      // 如果API失败，使用默认值
      console.log('Audit log settings API not available, using defaults')
    }
  } catch (error) {
    Message.error('获取LDAP配置失败')
  }
}

const handleSubmit = async () => {
  if (formData.enabled) {
    if (!formData.host || !formData.port || !formData.bind_dn || !formData.base_dn || !formData.user_filter) {
      Message.warning('请填写所有必填项')
      return
    }
  }

  // 如果是从启用状态切换到禁用状态，显示确认提示
  if (previousLDAPEnabled.value && !formData.enabled) {
    return new Promise<void>((resolve) => {
      Modal.confirm({
        title: '确认关闭LDAP认证',
        content: '关闭LDAP认证后，所有LDAP用户将无法登录系统（包括后台和VPN客户端）。系统用户仍可正常登录。是否确认关闭？',
        okText: '确认关闭',
        cancelText: '取消',
        okButtonProps: { status: 'danger' },
        onOk: async () => {
          await doSubmit()
          resolve()
        },
        onCancel: () => {
          // 恢复启用状态
          formData.enabled = true
          resolve()
        }
      })
    })
  }

  await doSubmit()
}

const doSubmit = async () => {
  submitLoading.value = true
  try {
    // 构建属性映射JSON（只包含非空字段）
    const mapping: LDAPAttributeMapping = {}
    if (attributeMapping.username) mapping.username = attributeMapping.username
    if (attributeMapping.email) mapping.email = attributeMapping.email
    if (attributeMapping.full_name) mapping.full_name = attributeMapping.full_name
    if (attributeMapping.member_of) mapping.member_of = attributeMapping.member_of
    
    // 如果有任何属性映射配置，转换为JSON字符串
    if (Object.keys(mapping).length > 0) {
      formData.attribute_mapping = JSON.stringify(mapping)
    } else {
      formData.attribute_mapping = ''
    }
    
    await ldapApi.updateConfig(formData)
    Message.success('配置保存成功')
    // 重新加载配置
    await fetchConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    submitLoading.value = false
  }
}

const handleTest = async () => {
  if (!formData.enabled) {
    Message.warning('请先启用LDAP认证')
    return
  }
  
  if (!formData.host || !formData.port || !formData.bind_dn || !formData.base_dn) {
    Message.warning('请先填写LDAP服务器配置')
    return
  }

  testLoading.value = true
  try {
    // 先保存配置，确保测试使用的是最新配置
    await ldapApi.updateConfig(formData)
    // 然后测试连接
    await ldapApi.testConnection()
    Message.success('LDAP连接测试成功')
  } catch (error: any) {
    const errorMsg = error.response?.data?.error || error.response?.data?.message || '连接测试失败'
    Message.error(`连接测试失败: ${errorMsg}`)
  } finally {
    testLoading.value = false
  }
}

const handleAuthTest = async () => {
  if (!authTestForm.username || !authTestForm.password) {
    Message.warning('请输入用户名和密码')
    return
  }

  if (!formData.enabled) {
    Message.warning('请先启用LDAP认证')
    return
  }

  if (!formData.host || !formData.port || !formData.bind_dn || !formData.base_dn || !formData.user_filter) {
    Message.warning('请先填写完整的LDAP配置（Host、Port、BindDN、BaseDN、UserFilter）')
    return
  }

  authTestLoading.value = true
  try {
    // 先保存配置，确保测试使用的是最新配置
    await ldapApi.updateConfig(formData)
    // 然后测试用户认证
    const result = await ldapApi.testAuth(authTestForm)
    if (result.success) {
      // 存储结果数据
      authTestResult.user = result.user
      authTestResult.message = result.message
      // 显示结果弹窗
      showAuthTestResultModal.value = true
      // 关闭测试输入弹窗
      showAuthTestModal.value = false
      // 清空密码字段
      authTestForm.password = ''
    }
  } catch (error: any) {
    const errorMsg = error.response?.data?.error || error.response?.data?.message || '认证测试失败'
    Message.error(`认证测试失败: ${errorMsg}`)
  } finally {
    authTestLoading.value = false
  }
}

const handleSyncUsers = async () => {
  if (!formData.enabled) {
    Message.warning('请先启用LDAP认证')
    return
  }

  if (!formData.host || !formData.port || !formData.bind_dn || !formData.base_dn || !formData.user_filter) {
    Message.warning('请先填写完整的LDAP配置（Host、Port、BindDN、BaseDN、UserFilter）')
    return
  }

  syncLoading.value = true
  try {
    // 先保存配置，确保同步使用的是最新配置
    await ldapApi.updateConfig(formData)
    // 然后同步用户
    const result = await ldapApi.syncUsers()
    if (result.success) {
      // 存储同步结果
      syncResult.success = result.success
      syncResult.message = result.message || ''
      syncResult.total = result.total
      syncResult.created = result.created
      syncResult.updated = result.updated
      syncResult.errors = result.errors
      syncResult.error_details = result.error_details || []
      
      // 构建详情数组
      syncResultDetails.value = []
      if (result.total !== undefined) {
        syncResultDetails.value.push(`共找到 ${result.total} 个用户`)
      }
      if (result.created !== undefined && result.created > 0) {
        syncResultDetails.value.push(`创建 ${result.created} 个`)
      }
      if (result.updated !== undefined && result.updated > 0) {
        syncResultDetails.value.push(`更新 ${result.updated} 个`)
      }
      if (result.errors !== undefined && result.errors > 0) {
        syncResultDetails.value.push(`失败 ${result.errors} 个`)
      }
      
      // 显示结果弹窗
      showSyncResultModal.value = true
    }
  } catch (error: any) {
    const errorMsg = error.response?.data?.error || error.response?.data?.message || '用户同步失败'
    Message.error(`用户同步失败: ${errorMsg}`)
  } finally {
    syncLoading.value = false
  }
}

// 获取VPN配置
const fetchVPNConfig = async () => {
  try {
    // 这里需要后端提供获取VPN配置的API
    // 暂时使用模拟数据，实际应该调用API
    const response = await request.get('/vpn/admin/config')
    if (response.data) {
      const config = response.data
      compressionForm.enable_compression = config.enable_compression || false
      compressionForm.compression_type = config.compression_type || 'lz4'
      // DNS拦截器配置已写死在代码中，不需要从配置读取
    }
  } catch (error) {
    console.error('获取VPN配置失败:', error)
  }
}

// 保存流量压缩配置
const handleCompressionSubmit = async () => {
  compressionLoading.value = true
  try {
    await request.post('/vpn/admin/config/compression', {
      enable_compression: compressionForm.enable_compression,
      compression_type: compressionForm.compression_type,
    })
    Message.success('流量压缩配置保存成功')
    await fetchVPNConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    compressionLoading.value = false
  }
}

// DNS拦截器配置已写死在代码中，不需要验证和保存函数

// 保存性能优化配置
const handlePerformanceSubmit = async () => {
  performanceLoading.value = true
  try {
    await request.post('/settings/performance', {
      enable_policy_cache: performanceForm.enable_policy_cache,
      cache_size: performanceForm.cache_size,
    })
    Message.success('性能优化配置保存成功')
    await fetchConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    performanceLoading.value = false
  }
}

// 保存分布式同步配置
const handleDistributedSyncSubmit = async () => {
  distributedLoading.value = true
  try {
    await request.post('/settings/distributed-sync', {
      enable_distributed_sync: distributedForm.enable_distributed_sync,
      sync_interval: distributedForm.sync_interval,
      change_check_interval: distributedForm.change_check_interval,
    })
    Message.success('分布式同步配置保存成功')
    await fetchConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    distributedLoading.value = false
  }
}

// 保存安全防护配置
const handleSecuritySubmit = async () => {
  securityLoading.value = true
  try {
    await request.post('/settings/security', {
      enable_rate_limit: securityForm.enable_rate_limit,
      rate_limit_per_ip: securityForm.rate_limit_per_ip,
      rate_limit_per_user: securityForm.rate_limit_per_user,
      allow_multi_client_login: securityForm.allow_multi_client_login,
      enable_ddos_protection: securityForm.enable_ddos_protection,
      ddos_threshold: securityForm.ddos_threshold,
      ddos_block_duration: securityForm.ddos_block_duration,
      enable_bruteforce_protection: securityForm.enable_bruteforce_protection,
      max_login_attempts: securityForm.max_login_attempts,
      login_lockout_duration: securityForm.login_lockout_duration,
      login_attempt_window: securityForm.login_attempt_window,
    })
    Message.success('安全防护配置保存成功')
    await fetchConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    securityLoading.value = false
  }
}

// 保存审计日志协议配置
const handleAuditLogSubmit = async () => {
  auditLogLoading.value = true
  try {
    await request.post('/settings/audit-log', {
      enabled_protocols: auditLogForm.enabled_protocols,
    })
    Message.success('审计日志协议配置保存成功')
    await fetchConfig()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '保存配置失败')
  } finally {
    auditLogLoading.value = false
  }
}

onMounted(() => {
  fetchConfig()
  fetchVPNConfig()
})
</script>

<style scoped>
.settings-page {
  padding: 24px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.card-header h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-text-1);
}

.card-header p {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--color-text-3);
}

:deep(.arco-card) {
  border-radius: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

:deep(.arco-card-header) {
  min-height: auto !important;
  height: auto !important;
  padding-bottom: 16px;
}

:deep(.arco-card-header-wrapper) {
  min-height: auto !important;
  height: auto !important;
}
</style>

