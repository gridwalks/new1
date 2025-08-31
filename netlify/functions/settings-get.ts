import { json, loadSettings } from "./util";
export const handler = async () => json(await loadSettings());
