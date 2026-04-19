package mist;

interface IMistService {
    String[] whitelistList() = 1;
    boolean whitelistGet(String pkg) = 2;
    void whitelistSet(String pkg, boolean value) = 3;
}
