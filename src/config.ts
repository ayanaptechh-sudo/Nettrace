import { ConfigSettings } from './types';

export const APP_NAME = "NetTrace";
export const APP_TITLE = "🛡️ NetTrace — Network Security Monitoring System";
export const APP_SUBTITLE = "Unknown Network Traffic Detector";
export const APP_VERSION = "1.0.0";
export const APP_AUTHOR = "NetTrace Project";
export const APP_LICENSE = "Educational use only";

export const DEFAULT_RISKY_PORTS: number[] = [
  23, 21, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5900, 6667, 4444,
];

export const DEFAULT_COMMON_PORTS: number[] = [
  20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 143, 161, 162,
  179, 389, 443, 465, 514, 587, 636, 993, 995, 1080, 1194, 1433,
  1521, 1723, 2049, 3306, 3389, 5060, 5222, 5353, 5432, 5900,
  6379, 8080, 8443, 8888, 9200, 27017,
];

export const DEFAULT_CONFIG: ConfigSettings = {
  learningThreshold: 5,
  anomalySigma: 3.0,
  minStddevSamples: 3,
  rateWindowSeconds: 60,
  rateSpikeMultiplier: 3.0,
  rateSpikeMinPackets: 20,
  maxByteHistory: 500,
  riskyPorts: DEFAULT_RISKY_PORTS,
  commonPorts: DEFAULT_COMMON_PORTS,
  reputationEnabled: true,
  reputationProvider: 'none',
  reputationThreshold: 50,
};

export const RISK_WEIGHT_SUSPICIOUS = 10;
export const RISK_WEIGHT_UNKNOWN = 3;
export const RISK_WEIGHT_ALERT_HIGH = 8;
export const RISK_WEIGHT_ALERT_MEDIUM = 3;
export const RISK_LOW_MAX = 20;
export const RISK_MEDIUM_MAX = 60;
