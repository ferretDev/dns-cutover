import * as enomApi from '../enom.js';
import { fromEnom, fromEnomSrv } from '../records.js';

export const name = 'Enom';
export const caps = { syncBack: true, srv: true, transferBoard: true, epp: true, redirects: true };

export async function listDomains() {
  return enomApi.listDomains();
}

export async function getZone(domain) {
  const [hostsR, srvR] = await Promise.allSettled([
    enomApi.getHosts(domain),
    enomApi.getSrvHosts(domain),
  ]);
  const errors = [];
  const hosts = hostsR.status === 'fulfilled' ? hostsR.value : (errors.push(`records: ${hostsR.reason.message}`), []);
  const srvHosts = srvR.status === 'fulfilled' ? srvR.value : (errors.push(`SRV records: ${srvR.reason.message}`), []);
  const base = fromEnom(hosts, domain);
  const srv = fromEnomSrv(srvHosts, domain);
  return {
    records: [...base.records, ...srv.records],
    redirects: base.redirects,
    warnings: [...base.warnings, ...srv.warnings],
    errors,
  };
}

export const getNameservers = enomApi.getNameservers;
export const setNameservers = enomApi.setNameservers;

export async function test() {
  const d = await enomApi.listDomains();
  return { ok: true, message: `${d.length} domain(s) visible` };
}

// syncBack (writing records back to the source) — Enom only
export const getRawHosts = enomApi.getHosts;
export const setHosts = enomApi.setHosts;

// transfer prep — Enom only
export const getRegLock = enomApi.getRegLock;
export const setRegLock = enomApi.setRegLock;
export const getWppsInfo = enomApi.getWppsInfo;
export const disableWpps = enomApi.disableWpps;
export const emailEppKey = enomApi.emailEppKey;
