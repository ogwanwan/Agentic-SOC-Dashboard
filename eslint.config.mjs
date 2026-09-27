import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // eslint-config-next의 기본 제외 설정을 재정의합니다.
  globalIgnores([
    // eslint-config-next의 기본 제외 경로입니다.
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
  {
    files: ["components/ui/**/*.{ts,tsx}", "hooks/use-mobile.ts"],
    rules: {
      // 이 파일들은 shadcn@4.17.0에서 원문 그대로 가져왔습니다.
      // 레지스트리 원본을 보존하고 SSOC 코드에만 더 엄격한 규칙을 적용합니다.
      "@typescript-eslint/no-unused-vars": "off",
      "react-hooks/purity": "off",
      "react-hooks/set-state-in-effect": "off",
    },
  },
]);

export default eslintConfig;
