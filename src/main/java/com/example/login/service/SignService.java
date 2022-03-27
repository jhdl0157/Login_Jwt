package com.example.login.service;

import com.example.login.config.JwtTokenProvider;
import com.example.login.dto.MemberRegisterRequestDto;
import com.example.login.dto.MemberRegisterResponseDto;
import com.example.login.entity.Member;
import com.example.login.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.omg.CosNaming.NamingContextPackage.NotFound;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
@Slf4j
public class SignService {
    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public MemberRegisterResponseDto registerMember(MemberRegisterRequestDto requestDto) {
        validateDuplicated(requestDto.getEmail());
        Member user = memberRepository.save(
                Member.builder()
                        .email(requestDto.getEmail())
                        .password(passwordEncoder.encode(requestDto.getPassword()))
                        .build());
        return new MemberRegisterResponseDto(user.getId(), user.getEmail());
    }

    public void validateDuplicated(String email) {
        if (memberRepository.findByEmail(email).isPresent())
            log.info("!!!!에러발생 삐용~!!~!~!!~!");
    }
    public MemberLoginResponseDto loginMember(MemberLoginRequestDto requestDto) {
        Member member = memberRepository.findByEmail(requestDto.getEmail()).orElseThrow(LoginFailureException::new);
        if (!passwordEncoder.matches(requestDto.getPassword(), member.getPassword()))
            throw new LoginFailureException();
        return new MemberLoginResponseDto(member.getId(), jwtTokenProvider.createToken(requestDto.getEmail()));

    }
}