from __future__ import annotations

import base64
import json
import zlib

import pytest

from conda_sigstore.exceptions import (
    BundleVerificationError,
    TrustMaterialUnavailableError,
)
from conda_sigstore.model import (
    AuthorizationStatus,
    Sidecar,
    SignerIdentity,
    VerificationStatus,
)
from conda_sigstore.provenance import SlsaProvenance
from conda_sigstore.statements import InTotoStatement, PublishStatement
from conda_sigstore.verification import (
    CryptographicVerification,
    SigstoreBundleMaterial,
    SigstoreVerifier,
    verify_bundles,
)

FILENAME = "pkg-1.0-0.conda"
DIGEST = "ab" * 32
IDENTITY = (
    "https://github.com/example/project/.github/workflows/release.yml@refs/tags/v1"
)
ISSUER = "https://token.actions.githubusercontent.com"
CHANNEL = "https://prefix.dev/example"


class FakeVerifier:
    def __init__(self, results: dict[str, CryptographicVerification | Exception]):
        self.results = results

    def verify(self, bundle_json):
        result = self.results[bundle_json]
        if isinstance(result, Exception):
            raise result
        return result


def verified(payload: bytes, *, payload_type: str = InTotoStatement.PAYLOAD_TYPE):
    return CryptographicVerification(payload_type, payload, IDENTITY, ISSUER, ("time",))


def test_one_verified_bundle_suffices_despite_invalid_sibling() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    verifier = FakeVerifier(
        {"bad": BundleVerificationError("bad signature"), "good": verified(payload)}
    )
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bad", "good"), prefix_sidecar=True),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=verifier,
        channel=CHANNEL,
    )
    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"
    assert result.failures[0].code == "invalid-bundle"
    assert result.prefix_sidecar


def test_malformed_target_channel_does_not_hide_valid_sibling() -> None:
    malformed = PublishStatement(FILENAME, DIGEST).payload()
    malformed_value = json.loads(malformed)
    malformed_value["predicate"] = {"targetChannel": "https://[invalid"}
    good = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bad", "good")),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "bad": verified(json.dumps(malformed_value).encode()),
                "good": verified(good),
            }
        ),
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.failures[0].code == "invalid-cep27"


def test_valid_signature_with_wrong_artifact_is_invalid() -> None:
    payload = PublishStatement("other-1.0-0.conda", DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
    )
    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-cep27"


def test_target_channel_cannot_be_replayed_to_another_channel() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()

    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel="https://prefix.dev/other",
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-cep27"


def test_sigstore_parser_rejects_unsupported_bundle_media_type() -> None:
    result = verify_bundles(
        Sidecar(
            "url",
            "cd" * 32,
            ('{"mediaType":"unsupported"}',),
        ),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=SigstoreVerifier(offline=True),
    )

    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-bundle"


def test_any_authenticated_signer_is_reported_without_authorization_claim() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "bundle": CryptographicVerification(
                    InTotoStatement.PAYLOAD_TYPE,
                    payload,
                    "https://github.com/not-the-publisher/workflow",
                    ISSUER,
                    ("time",),
                )
            }
        ),
        channel=CHANNEL,
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].identity.endswith("not-the-publisher/workflow")
    assert result.evidence[0].predicate_type == PublishStatement.PREDICATE_TYPE
    assert result.evidence[0].timestamps == ("time",)
    assert result.evidence[0].verified
    assert result.to_dict()["authorization"] == "not-evaluated"


def test_explicit_identity_and_issuer_authorize_exact_signer() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
        expected_signer=SignerIdentity(IDENTITY, ISSUER),
    )

    assert result.status is VerificationStatus.VERIFIED
    assert result.authorization is AuthorizationStatus.VERIFIED
    assert result.to_dict()["authorization"] == "verified"


@pytest.mark.parametrize(
    "expected_signer",
    [
        SignerIdentity("publisher@example.org", ISSUER),
        SignerIdentity(IDENTITY, "https://issuer.example"),
    ],
)
def test_explicit_identity_rejects_other_signer_without_hiding_evidence(
    expected_signer,
) -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        channel=CHANNEL,
        expected_signer=expected_signer,
    )

    assert result.status is VerificationStatus.UNTRUSTED_IDENTITY
    assert result.authorization is AuthorizationStatus.FAILED
    assert result.to_dict()["expected_signer"] == {
        "identity": expected_signer.identity,
        "issuer": expected_signer.issuer,
    }
    assert result.evidence[0].verified
    assert result.evidence[0].identity == IDENTITY
    assert result.evidence[0].issuer == ISSUER
    assert result.failures[0].code == "untrusted-identity"


def test_unavailable_sibling_takes_precedence_over_untrusted_identity() -> None:
    payload = PublishStatement(FILENAME, DIGEST, CHANNEL).payload()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("untrusted", "unavailable")),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {
                "untrusted": verified(payload),
                "unavailable": TrustMaterialUnavailableError("trust root unavailable"),
            }
        ),
        channel=CHANNEL,
        expected_signer=SignerIdentity("publisher@example.org", ISSUER),
    )

    assert result.status is VerificationStatus.EVIDENCE_UNAVAILABLE
    assert result.evidence[0].verified
    assert [failure.code for failure in result.failures] == [
        "untrusted-identity",
        "evidence-unavailable",
    ]


def test_missing_offline_trust_material_is_evidence_unavailable() -> None:
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier(
            {"bundle": TrustMaterialUnavailableError("trust root unavailable")}
        ),
    )

    assert result.status is VerificationStatus.EVIDENCE_UNAVAILABLE
    assert result.failures[0].code == "evidence-unavailable"


def test_slsa_provenance_preserves_untrusted_signer_evidence() -> None:
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": FILENAME, "digest": {"sha256": DIGEST}}],
            "predicateType": SlsaProvenance.PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.org/build/v1",
                    "resolvedDependencies": [],
                },
                "runDetails": {"builder": {"id": "https://example.org/builder"}},
            },
        }
    ).encode()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
        expected_signer=SignerIdentity("publisher@example.org", ISSUER),
    )
    assert result.status is VerificationStatus.INVALID
    assert result.authorization is AuthorizationStatus.FAILED
    assert result.evidence[0].verified
    assert (
        result.evidence[0].details["provenance"]["builder"]
        == "https://example.org/builder"
    )
    assert [failure.code for failure in result.failures] == [
        "untrusted-identity",
        "missing-publish-attestation",
    ]


def test_unrelated_slsa_provenance_is_not_reported_for_package() -> None:
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": FILENAME, "digest": {"sha256": "cd" * 32}}],
            "predicateType": SlsaProvenance.PREDICATE_TYPE,
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.org/build/v1",
                    "resolvedDependencies": [],
                },
                "runDetails": {"builder": {"id": "https://example.org/builder"}},
            },
        }
    ).encode()
    result = verify_bundles(
        Sidecar("url", "cd" * 32, ("bundle",)),
        artifact_name=FILENAME,
        artifact_sha256=DIGEST,
        verifier=FakeVerifier({"bundle": verified(payload)}),
    )
    assert result.status is VerificationStatus.INVALID
    assert result.failures[0].code == "invalid-provenance"
    assert result.evidence[0].details == {}


# Captured from Prefix on 2026-08-10. This fixture is never fetched by tests.
PREFIX_ACTIONLINT_BUNDLE_B85 = (
    "c-qZ++mfqDlI^dw?bocS1SFKHF{=j<1Oh3L2p|HO?guUscY!1%E^Tc#A923$e91VOb=j3Y)opVzJLe%y2?_!a_vO"
    "o%E8^e&`mH`CdFYJo>D#}43){BJ<FLz{%j@%!{Ft1cKi>27-Zi(=kJ00jRHq-G+>eWw;@(`o{qXI1y5;AeAHZP;S"
    "7G(-U;p|oKHa*{FHZC2E$rp7JKf<8Sl6|iv)RbSA(eVvmQvj%r}0?p%6ebkJMJ|*$hYCS6DNDgOZ_JG^<5L_Q^Bc"
    "Hk9%`cDVDJ&@vgebFph=l5--RzuH8qVQ2~=>zm<H2T9%>?bP8EACE9unY`%>yq>5|43bZOqG`HVov55=6#}gi~qV"
    "op@5A1jMaQ|_ykR*)CUhVzu&$etN>sPxJ$%+*#mDF@qJyc07hm(E1YfF(^7tw{v=U6iFdNWpwuDnO@Wn3p){hTNj"
    "eQu67%Q4e-{dQ36?ER&btHaRToOf;Th}=Fd+;er<$W-sslpe6OoY$Qwy(+)<7WhNori$dqsY$oCt161LlhgDjrz("
    "=cCTWtAkMFFdic-rhJu$sH^<h}})=*-+ZSt#rJwBQ4_uC$PMz}(j(;hXFyI3FFiT6u2h{UT|v^&J|Az%7|^4|OD$"
    "5<j++gBN-J#7Lv+!8L{;?;g!UqX*G3DY0Gu<rIk#z%Eh#rgW_L!96q#7TYb>!eMzjQ8{PB3c-?pdOyd0zV_c<lyf"
    "a)g;?rsw`rI6xXzl$8{4hRKjQHv+9ABQrqNrO|mRGeS7aEOI3G5#wA;MI^^$9i1{sG%ZJZQE@bORJc>WtW$>{;$J"
    "vfVqmN`G7Lma9DD`){-j`)bQ=XFqxU}?GFyWnqj{qy?*YA6)!IQN#i&!`~{)i`a#C1>x8p#699fDftO~D=f!dl=W"
    "t1*l*3u);)k|(Fl93xfo53g8KRavUO_f5b3@-Er3tZ+*o0oc74)&;B$Y!*wHEBP{)CQE>I7EIvx%4Y;V`7C71{?P"
    "w^P5^MHY`P}dl0KfA=N{f43iPqB5zJpbqYH-jRUEuGPdpRy24VvF6J4y2xMI!v;{Q^m>G1ym2k93(8g-ZU|J~Sp_"
    "2*ue-m$`dv5{}0g~<iX0w(&sKY;`)Wn=#4PvMtmKJfMYgZM4Kyw8+34c;l3J1G9bEJ^_vz(a*mgY6~6v%)OMO(%g"
    "*oiitW85F88^VMO-%~zXJizt792ki^Sl-|OM)Bxv|;{oh4m6*euFF8g4V0|C_(-;>L{jx41OEH$6cmi7&e}^5S|N"
    "ns<g8wJj@xQFum8Ax6wq_A(v`pAgVHAIPpR3x|u>G&D`!`Noj|mf}{iILk6fbe%0v05GFCY%Mt&6u1?@9eTZi8B&"
    "D^kz{7v4jL`_ylKwTr)$8(GrTvqV<XHkFc8Nsf+u9quu~H4e7f7z9(iY0CEWFqiMQ^UF5B?4<p8c@(K6NdYhOvRA"
    "=>P@m*2R^5$`?90=ul6JaxEgd>?R@yUC9+y7Tk(x*62VUB{g|j<^3n_=khV!f3`A>$+Wo^9Q?nQcem!vSiU;M%~h"
    "n<t;M<liHNByflP(n%S14|zyBh;n-<ybW|JF4EpN>AhDjfCS~bXhJkbYI9qWb;L^93(qbHvXG3oRqbXagtulmP&f"
    "BuZoB4(B?HfZQ9cd8QA;FOLcAOs8%<@H-_+KnI5gOXj8TlyS`Go{ZTo4?{)F=x*el$fBWHES2d}6>2CR~e*W#R-{"
    "4ZeB&PwS5HD~7FRnyU1SK`!PiC!Dp2qo~Z@sCn!_LyG>4mcMVYMe?x?NiC*?)a!OM?2`5p$7|ROWt~UsUFogr079"
    "P+}j`z$MI*-0!DPo%Z>~H||I7M}8ikU%FFz1A&$}c|B`C{_SnK7Q{8rf1AIJtH=Dv@z&J&{X@lp5WJj{c`@Vs$h`"
    "~ec2;z%ztOEt^1>IDAMw13-3P%BUop|BOg+zAmhbb^x;cw+uUy_FOV6Z3{UD~hT)rJRyKYlmTt&I`+|w0(+L5G2O"
    "cd)q)?5ABeH#0lIn8-C=6gSK@0=hC!g>LQ!}r}byk~H~6gsol&BxorSXl<nF}*!*^*Sd7d2L@)Lo%%Pox4ljw)_d"
    "6>~5!%olmFlXI#Sl3}*WX-Z$!E71cZ5z3)a74NkmHh1dNdjb!OiI(rWvrWfgeukW@sPlz<je;rQIj^Dl>!>#rZ-%"
    "ah-trgCGSBH`dWF#Qv-CxM>^YCF&iPkCROLhH5Rb;PL+I96ZxWaHfO2gZ&2-*cFR>ATSe+(CSWt+a`+w(2*$8aC?"
    "$3=ykDrg>WFE=YbTeLoHP1m~K=i%j3j=48uG3<-w3-0Rl9G~BJ=5$g!cPXw$U^F{5&bX%^!_h?<^PXRv-<Ebg>54"
    "}E#=q3>>Aq-}N`H5U9ltodT2B07`!YAeht4_1p?|OH0G0Y<<;8F19R#8_9d6QnL8s|ih{?zB)%GzO2R#nT3z3+M?"
    "wPUS@=@>io1=Cyp3cDga`Q~h(}yG1O|ywB#kz1g;hbpkyddDnSG|vF`Q`MM8)qkZdPbRVxOsTkNmagI8@Q8=7wWI"
    "Q?zknz`?U7r+w$dYBfdF3$6@VV_*m-Wh40l|A!g%PcYb<$Leg8Cg<sjdg~YOT`u18Hd6A3$Jls%kMfsFy5S7EIJN"
    "n_WZhiYGjj3IqmtMNI-p~6iSRD`jJX|?!PK}M5r~ceS&@=s+-<y6dJxnh>vHMcplp|TG@zr;K`u3L}zQx%oF53pO"
    "b4K~;@;p_|M{9OFmCfz9W(+#BKmE&}czz9-;MU@L&97F#CEV)Im*3F)=gWU32mXBd^X32k`~UgVfAXdeGAcmiWb1"
    "673p&GvE_9e1Y~{@N(@P~4<y|wn>b~XFrA$oraHU*Y_LhGzM`yitNgj#nvGBO6KAiE{RWov4S4(ucJ1Z}d`=8+T-"
    "~I-v9*39a0-a+8shG%3GQ!$Vqmjj0#RAWm=EA2JO^!FqeqX5heq-E1CYJNPU~5i+t>5*F*#`{ghs!+=m?#8nc*Yv"
    "lea~$4qJ7hAbPt5}I2YT<)>kmT@f|4a`TT5<MO#{ZyrYnMlewcgm4oSE0Tj{_J4xX?Af^ff{`B6|NO8~zh%$G?iZ"
    "29;QG<8@VdgJQK^6QW9s^Am4^BK{0Tn@Rtik5q_o{m&pwiaR6mIm@yv9gNppga9t#SDwhqY?zXgdD9M!{zTAI!Ga"
    "s5Bi~2Srkw8i+uJmatagz-Ifh+Emi%z*He9@FFN^2_j|*f(z!cINt%Gs7Qm!)CG1h<bc2M3%P`O^0VFNb2A;)ARa"
    "uUibs9L7Wd!Xn|<QAlvrG)pIk$URJ6D1^^&oGvo2^d%hq={YduEENa~VzoN6%LHr#Vi_f_JBs0uAs$+QHu=Zcokt"
    "jVNpOD{=yqJe%Y*R3-_b5>M2-4bFiki6qFgtzK~Xf3iFZms8ip44;<S<nWaKKlu~lgv2?4;F9GKyBU7HB`3>c9fc"
    "wl`Y7+fVvg#6LoO#mMGzbb}mm#cqej7LLyJLSRreeH>q73A=U;)8P7~gx7clMq7A0+m<O!#%7Lw+476h4W}%~sev"
    "HV0sKF*s<U>>?G*X8gd-5(|{4)W2NMX86Gxt;zdr}2A?3ylRWaCh1Eh}{lRnes!FZyN7hb3fGVFb89EI>hTqu^?n"
    "A`L5jayhE8%9#HsrG^%`L1<Qx6IxeA)X*J1yZe-`$R!CPhdO?V`mi=!axuM7Ad~MVHq7S-YLyXAJW`bOtcFI$3Bb"
    "PW;Fk1uLRRmVVnu55WRAo;kSCD>_HX4w;JO2$#1D{c6G!D}Vf0poD0Y(!3q%VPbhlmemTUufUk`X~Hv}PAW9v|l2"
    "vq3qW{s{^NeLkK>Vl+>;CWh$hsXmwR1{&R0_F#bxnSj9AZ{+NMq4zm$8#AUhA`fA!FG4a`z1MGO`ROK3&J`ZnWGO"
    "OZ=y)!Lqd%S<_!s=x?LHJIP~Fj<c4{xrx%hDEg5}B-o?B%h1;NrkjlA**)U3P_9ZFlL>7V8hAvWjyGk6Ukq0XfT!"
    "RN3*-jSnNBlzG&;vCfp;Jx}6lQ@xBee=KGB&iNyQm^}R#p^KXdOywTYy0u?802D0Nxnk(Vf(QFV`1bn%EZK^d?Ol"
    "Qo23(BaAA_=*92|3LcgqYLprD;1CnD!4BMnb1Fi?{*0-?&gX*-uKYeiZHcvXqCB<X?+STILau!PKEtF!jC$>nmc}"
    "Art;TA#r!@*fP!&|;`-I0mtFjF6&^u*tv-#xaf;I5I$FK8M<{Ur6QRE%rn<+rajCTgUYg~@sI%VZj)S3Y$_k>m~L"
    "}rdF!*}_Nv68<=itG}#eL6JRC8*t=v^Jw!KT@6?T!CC-cs8v20q{}+4sWL|32oK5xrK2#p~MR(YT~k5xq`U!nc;_"
    "u5fW8A1R8IgD7jj7WrmYGGRA>+Lg=)mIT5m!LVT^N95GFD$}M?^k42yQJ-Yypx$|{qv&tV&3UVR8Mz@d;v4;CVg?"
    "uXmg<aah)GWwh!=^OA4&yHg-=a`8t8l7%hs#31!z$WVUNk?4f;&UAJsCT}dYEJ0Ff%$*RWx$4Ju8FK=6KKXDi+m4"
    "=&<&VX^X(0CFKp(sggc)`Kwi!cEm_Ha~$Rq;3x1u14ICyK>poGEdug}tHbVmQYH5QnI`30omN@t@XZj-oF~BZ3}g"
    "+DfFEfYUF40+I^a9%9bB=BRJWhwAC~;>K&i*H;SjJ6_>Xv)p$y`y10Oa%)dyM-FLKb%p)Lpf>4&JzA{B%?@JS>Xf"
    "c1~(k3Q=VR?T~aAm8f@@UDv|iaN*_n*w*yZ7Di){+EzHTrdUNa647>!K&}$Z}p)jdcYre<`=O4M#>C$tbu%?JBtT"
    "TR7OBq=7GPTV9z7uI>1-S`;5136*Qj)c&GxvR{;6fBFMk|*ZhNgh>(o2f;NzECCu+e3WfMVv(LK4iJ|QYwG6wB0Q"
    "Ji_X=qET>|kren(cv_1Nd)Au#gq7rzDI#V%324h#N{Xn^1LfFF{CH=726Zn6*AZ4wx|C$SB!Sfl$D=4fSWn_YzlC"
    "2mDsjdJXk}Y#?_uc9BC;XGgzG4haGts;fLw+sP96T|%i(KmFBHL`%2Qd*>n-SR?TMK(qLE<xh~m;B(+RMj>BA6wL"
    "l|95*@Gl(=9|MYVxvG-zBwAKfZ*7*N6o9uZOPdOhQbV`Z|i`ErE(D<iF2Q6`3;`HbfJqCp*6LO$zO-PyQKmK3<db"
    "h**?S|=*o%&)QrSFP%lVi~!WNVRqY_`aEr0sM{}-=)ih8QTza9u~6A%;!`vNUXK9eNaD!k_hVP6!gfD5z^UT04=u"
    "`ZLEsDKgp#9d`U_(Jk?M^6j^g?y{F|60{#VxvbnY)(?h|jY%Rdu9q{ePYEV%Jaa7>B8Q-v8CECh!{xrZZG+bnESh"
    "fu6?LDT{1^cszWgJC;&1z5>9u$Syo|0-I5BP?9GV?9qiCLfr4%@&5ylYeiyq0T(q51<KE?5bE<ah?}GU)_-z}kbu"
    "@mh>B3iamjJ-%SR4e$~8l>+`vs231Vs3!!G?!Y===w<?b=@a0~WKn(LOO(z2c0jLu;HiLkm8}<0)H}d0P+tL`c+M"
    "B&<cc1|kP#Q^593Qvm^a9mneR4~cb5s&8&U=?*rWP|G&slrZI-xD??MOkLd?(#^hy>^pbvl#Y{6i$n$gH35HGZgI"
    "p9E=c@Z0+1|@dP69#(CB#tY%Jh6R-Zq$SNv5><+kwhCAvtF6&4`@8IWWaZz&uonJ5%Lr8ZEOPsG2)HQr~dJWSP4G"
    "ri(k(COCQk(A5=@wKN?d-sMlHe59ZThzM20wKGX}RGPa2VZ9iN)C0IzSl~sxaUx@BH#{C5OMrJ+cwh!mhHke0jp3"
    "eoo3>343<fPzp6ZDorp$t2Wy3kt$z=sa>4>m*QZ~3c|9pJ&UFC-+3><av;(SL*|*6pC4^`Ivi;g*6W+=rMZGd^wX"
    "2LHgm)`oXJ0MB!6)@&~cFz7$0?v|#z_DtYXQntcJeX0oy7uB3^=3MVisOm85pbHm!@OJ?Ez;!Bf<^vI~8RSn7dFh"
    "e~-Fy!8riN6|e^B4M)r@ajFz+!isEyhi;AH^51AV&&|IB<Kh9NT;<R3gwXT7>(8hEX4bFi12>!-<#MXVu)Q9FKK6"
    "D>kn4!RcfYf{=s9iwe)&wK}ZY!{W{DpY2@(jLHnTvS`*f1}>be855UHOSBVT>k){_G~}k9r^>2k-F#S`2ZW*XT2N"
    "#xZYJC^$z%m&ivcOT4qDtA7_7?8sw8Z$HUzJVf-qX4`K``X#R)s1OEQ#H#`dUGC-*RIes3k$<g`9m$gspnSXm8<|"
    "{CR9zh8l=m(C_-<VJzych+bx6lA>p$2?%V_pJ$LcBno>kEZ?$X6lnPj1aazCjPBm>#U>vtGI;=;{DSyxjsXX`t01"
    "-l+W0i-LFvkq`ZeIp?eJRgXC|=Hm+Vd1*MnPn}Bx1A~7-FA&gA55R*B_mF+bDq9t=l-&oYpA7iGAwtSSJ?Txz9|!"
    "t<%o(7YTn?*i-LCmP__O!xj<YJFL%x;}?+4hcLH=EVe@(DA0RGji5B*|5eQhDXL92s3k(y9kxFh9~Whj_>ylqR%l"
    "NZpBG#Jqic)uWgyLHQqCCq~UueC!y=o$1kP|sYqBF+hVK6jGDQ001ZkpVyc1bROJ{SG|PLcWoM@3nS<%xk!<3Ve|"
    "te%*q;MIM>!e?ddg2R*IGBUA_IGmM_PaIZGi5TUuBQNiDLyTapvp*fxd^z|S83)ClQmgjyJK@Vd3p=vmh8|++~6>"
    "&wkr)|KX{t@V}n_26DZmZyV5EX#|dRDbOhzG<M>PbTcbLD`)BDZxx@Atkd>M$S0C3xFG(2p59^m}uE9a7{%|JICv"
    ";Q}~g1N}k?wWNy`L?UE({-qQ_Yf|Tugzkbs*BTV2+RYn3xvd7Xf1#H$bla;yFG?Jv=7do*Se221e-^Ob0+*r>eO^"
    "vxoI}q}XnPMPl2c(lLO;`(w7NtK^7HQrlsUYiSS5jcYpKiA(1!SuirPQ_-q0tic{w^<ey05TZ2k1px4-@6hi~04z"
    "m3!H4o4_q7k-?CIL8Zq#sB*I`RAs<=P&EO`%zuj)m0%WQmRVx|4Yj^=53Db8Jm(7ZyLDA6`PHWmmA5#gW^bgIjz#"
    "HOy$7BDm>SxG1fNYRkQVIp;)S+N~+rE+9c~*k9DnsF|wSN-)&jxkZqFrWga9+R$3U>?b)Ug(q2>9_d~h4ipN8)8l"
    "5*>k7Ih@Uk(<zqLZs`kfj`LEbiW2^>}k9!!wqv8(S)&f)iCvkGPQLEwc$vY7d#R#FG(X3Bx+n&Bod++=dyqTaoK4"
    "X>1i~{*~{a9QknPqZyw^KKkMNBOhEWXla`2F8FYxDw~ZIgufm;Ib^20??=l&t=@YVKgZ?ukdIA~_x;};J2^Q2#0F"
    "cMx9xvEc9MLtLG5CJ-h+$T27*|DvN@ri8%;;zu#)y>;fkhWhH!8CyyyRV4{w$Oaz2lE$Wr4dTbN^Ea)A13Uy~~N&"
    "Nom`zqhMPwq}O6eh<O@{@4oIEg{|;UGY;%UEV?=c+Ylbo(j&oM8!sO8ckbpMLE7O>$#Ap{Y$-jX1u*K$*bEx`uo}"
    "3q|5tlY<wwsS6BJHc~WVCmtkWj_1aQ$kqh20jygWC=~+2;j^2BEch1?Xgw8yDd-P>gN=?BHL)-{WA1cz}^O(xJES"
    "=v~8L%KP!JpR0F_VKV`zq2e>yvxfPHVX$cf29@_#X4!x;xwzEWdvoi_v?_$8snkqqs|__3MM*zVe29ik4Ts2A!J6"
    "t5+=hA7c&c;|LALQlo7)^VX+}WXOuoYseYAT!S5oB%~77+znQ`_D)|{yYRqWNA&9AyC;Mo^mZ0X8qH}tON+U4cje"
    ">zquL%dZI#^X5u3@vkYBWgI&VoH!s02%MQhZ%XlXuQ1Sf2YcQ+PaqE())khj_FZlQgBv?uOuy54&n1DT%qSRJ0*="
    "d+r$jg&Nfnr_*gyBMkeySSA8Nlx^>;p>4eF;|f#U2gR4JC?y;_HP^`O)Bum{hF1zw(dE3LnK*Nq!@VSw|ka5D8t_"
    "!y&72|J%2yW8uZjkH@(=u%9*?_g;=|DH)G$tEbdz2HK%YorjNj4u2q&=<Me&%FTZe}{>0vUe|F?Iye(B-_eA5Z-("
    "H3Nu74v6y{m^;T^olceHAWOQS7o_NYvG2u?0qMe+;cRtd##O2U9FBf5}1bYYy%`vx>A}_WdJZ)&?n!LpSfZ)V7Z&"
    "M#}#Eu`8PURbSrm7yNBx&F>*D{qcT(HtE7S7E%(mZLixea@(xET;Pvs<oB#kEVt>(BYy9cr~3@{@=ZCZm6>fW@lE"
    "oiLN2CD8ceYtk}BTcNb4Squ_xyjX8Woj$^|Ki$dA|NY9%j+O5fo8?BCBXrH-Sv7lnD3`7iSZ&Ag?o{<<&q*Kch&R"
    "!x}v!3o0r@-JP}HNPAf{CV)_p3XVhR{iIm#%~9=LbmJxp<FbIZ8WZ(L_-{C&H3QbGx^-_nG$AP17>o1(MB-O1GL7"
    "+-o!5lBO<MOBpYtn7x4o-dKUtt28z3Yp6rZ24t$BFKkpOO1dvas<a7V!*Zr15Zd6!sdr-VQWKm%<y+1I0IA})ZGr"
    "Tk>T?`bJ!;Z=y9BJ|kngv==LNx>CrZtSq{i5uB$H=i@RHg&Ein*MA;n&{0&$2b<Lx_d%ftvVFeDHbjjL+in7h6R@"
    "Q~ZSST;Q1;e710Z+IuqZ*Fzf%X@_lb@`bF5nED7W<}>=(%aWn5C9N-j5ABaN!n4LD@Q4y>=n>WQKKt#v11SA`P$u"
    "-!5BB)&5EBpc43$401RIS{t@Fc&Yze!^?ewdP`8W<>ZS?IZZz^dgH-mrf<m-K9c*oam%Wfza@%kzn!Rsz}6qfmcl"
    "uLBWTjnuL7GjXoJ{aj1yl@b2(K>QEYj>4iJe9k?DTONi^ohd1{0Fw5QTh"
)


def test_captured_prefix_bundle_verifies_offline() -> None:
    raw_sidecar = zlib.decompress(base64.b85decode(PREFIX_ACTIONLINT_BUNDLE_B85))
    bundle_json = json.dumps(json.loads(raw_sidecar)[0])
    expected_identity = (
        "https://github.com/hunger/octoconda/.github/workflows/"
        "octoconda.yaml@refs/heads/main"
    )
    identity = SigstoreBundleMaterial.from_json(bundle_json).signer()
    assert identity.identity == expected_identity
    assert identity.issuer == ISSUER

    result = verify_bundles(
        Sidecar(
            "https://prefix.dev/actionlint.v0.sigs",
            "d6dfbfcf1f3fdc2821ddaf525427461b9a68b879d70c265b67454cfbdcdb9c16",
            (bundle_json,),
            prefix_sidecar=True,
        ),
        artifact_name="actionlint-1.7.12-h60d57d3_0.conda",
        artifact_sha256=(
            "e3e0f35dec5b09b18baac8729d14115903b5adfd25065f8bbb90a2b3be5401e4"
        ),
        verifier=SigstoreVerifier(offline=True),
        channel="https://prefix.dev/github-releases",
    )
    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence[0].identity == expected_identity
    assert "2026-03-31T02:58:32Z" in result.evidence[0].timestamps
    assert result.evidence[0].predicate_type == PublishStatement.PREDICATE_TYPE
    assert result.to_dict()["authorization"] == "not-evaluated"
