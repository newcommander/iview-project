<template>
    <div class="layout">
        <Layout>
            <Header :style="{position: 'fixed', width: '100%', padding: '0px 24px 0px 0px'}">
                <header_view :data=header_data @set_sider_data="onSetSiderData" @set_content_data="onSetContentData"></header_view>
            </Header>
            <Layout>
                <Sider width=64 :style="{position: 'fixed', height: '100%', top: '64px'}">
                    <sider_view :data=sider_data></sider_view>
                </Sider>
                <Layout>
                    <Content :style="{margin: '88px 24px 0 88px', background: '#fff', minHeight: '500px'}">
                        <content_view :data=content_data></content_view>
                    </Content>
                    <Footer :style="{margin: '0 24px 0 88px', background: '#fff'}">
                        <footer_view></footer_view>
                    </Footer>
                </Layout>
            </Layout>
        </Layout>
    </div>
</template>
<script>
    import header_view from './header'
    import sider_view from './sider'
    import content_view from './content'
    import footer_view from './footer'

    export default {
        components: {
            header_view,
            sider_view,
            content_view,
            footer_view
        },
        data: function () {
            return {
                header_data: "init head data",
                sider_data: "init sider data",
                content_data: "init content data"
            }
        },
        methods: {
            onSetHeaderData: function (data) {
                this.header_data = data;
            },
            onSetSiderData: function (data) {
                this.sider_data = data;
            },
            onSetContentData: function (data) {
                this.content_data = data;
            }
        }
    }
</script>
