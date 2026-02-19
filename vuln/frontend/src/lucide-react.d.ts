declare module "lucide-react" {
  import { FC, SVGProps } from "react";

  interface IconProps extends SVGProps<SVGSVGElement> {
    size?: number | string;
    strokeWidth?: number | string;
    absoluteStrokeWidth?: boolean;
  }

  export const AlertCircle: FC<IconProps>;
  export const CheckCircle: FC<IconProps>;
  export const AlertTriangle: FC<IconProps>;
  export const ChevronDown: FC<IconProps>;
  export const ChevronUp: FC<IconProps>;
  export const Loader: FC<IconProps>;
  export const Shield: FC<IconProps>;
  export const Info: FC<IconProps>;
  export const Wifi: FC<IconProps>;
  export const WifiOff: FC<IconProps>;
  export const Globe: FC<IconProps>;
  export const Search: FC<IconProps>;
  export const Clock: FC<IconProps>;
  export const XCircle: FC<IconProps>;
  export const Zap: FC<IconProps>;
  export const FileText: FC<IconProps>;
  export const Download: FC<IconProps>;
  export const Filter: FC<IconProps>;
  export const Eye: FC<IconProps>;
  export const Trash2: FC<IconProps>;
  export const TrendingUp: FC<IconProps>;
  export const TrendingDown: FC<IconProps>;
  export const Activity: FC<IconProps>;
  export const Settings: FC<IconProps>;
  export const Bell: FC<IconProps>;
  export const User: FC<IconProps>;
  export const Key: FC<IconProps>;
  export const Database: FC<IconProps>;
  export const Mail: FC<IconProps>;
  export const Save: FC<IconProps>;
  export const LayoutDashboard: FC<IconProps>;
  export const History: FC<IconProps>;
  export const X: FC<IconProps>;
  export const ChevronRight: FC<IconProps>;
  export const Server: FC<IconProps>;
  export const Menu: FC<IconProps>;
  export const Loader2: FC<IconProps>;
}

/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
